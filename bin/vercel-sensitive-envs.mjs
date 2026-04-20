#!/usr/bin/env node

import { chmod, readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { parseArgs } from 'node:util'

const API_BASE_URL = 'https://api.vercel.com'
const PHASES = ['production', 'preview']
const DEFAULT_TOKEN_ENV_NAMES = ['VERCEL_TOKEN', 'VERCEL_ACCESS_TOKEN']
const SENSITIVE_FILE_MODE = 0o600
const DEFAULT_JOURNAL_FILENAME = '.vercel-sensitive-envs.journal.json'
const JOURNAL_VERSION = 1
const MAX_REQUEST_RETRIES = 4
const RETRY_BASE_DELAY_MS = 500
const RETRY_MAX_DELAY_MS = 5_000

function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

function printHelp() {
  console.log(`
Rotate Vercel environment variables into per-target sensitive variables.

This tool always processes production first, then preview.
It defaults to plan-only mode. Pass --yes to perform writes.

Usage:
  vercel-sensitive-envs \\
    --scope project \\
    --project your-project-name \\
    --team-slug your-team-slug \\
    --manifest ./examples/vercel-sensitive-rotation.example.json

  vercel-sensitive-envs \\
    --scope project \\
    --project your-project-name \\
    --team-slug your-team-slug \\
    --dump-non-sensitive-manifest \\
    --output ./vercel-sensitive-rotation.generated.json

Required:
  --scope <project|shared>

Required for rotation:
  --manifest <path>

Project scope:
  --project <project-id-or-name>

Team context:
  --team-id <team-id>
  --team-slug <team-slug>

Optional:
  --include KEY1,KEY2
  --exclude KEY1,KEY2
  --allow-git-branch-vars
  --dump-non-sensitive-manifest
  --output <path>
  --journal <path>
  --resume
  --yes

  Rotation mode writes a local journal during --yes runs.
  Default journal path: ./${DEFAULT_JOURNAL_FILENAME}

Manifest shape:
{
  "entries": [
    { "key": "PRIMARY_SERVICE_TOKEN", "production": "new-prod", "preview": "new-preview" },
    { "key": "NOTIFICATION_PROVIDER_SECRET", "all": "same-value-for-production-and-preview" },
    { "key": "INTERNAL_SIGNING_SECRET", "production": "prod-only-secret" }
  ]
}
`.trim())
}

function fail(message) {
  console.error(`ERROR: ${message}`)
  process.exit(1)
}

function warn(message) {
  console.warn(`WARN: ${message}`)
}

function info(message) {
  console.log(message)
}

function parseCommaList(value) {
  if (!value) {
    return new Set()
  }

  return new Set(
    value
      .split(',')
      .map(item => item.trim())
      .filter(Boolean),
  )
}

function normalizeTargets(target) {
  if (!target) {
    return []
  }

  return Array.isArray(target) ? [...target] : [target]
}

function appliesToTarget(envVar, target) {
  return normalizeTargets(envVar.target).includes(target)
}

function isGitBranchScoped(envVar) {
  return typeof envVar.gitBranch === 'string' && envVar.gitBranch.length > 0
}

function isRecordEmpty(value) {
  return value === undefined || value === null || value === ''
}

function looksLikeVercelCiphertext(value) {
  return typeof value === 'string' && value.startsWith('eyJ2IjoidjIi')
}

function hasReadablePlaintextValue(envVar) {
  return typeof envVar?.value === 'string'
    && envVar.value.length > 0
    && !looksLikeVercelCiphertext(envVar.value)
}

function buildPlaceholderValue({ key, phase }) {
  return `REPLACE_WITH_NEW_${key}_${phase.toUpperCase()}_VALUE`
}

function isGeneratedPlaceholder(value) {
  return typeof value === 'string' && value.startsWith('REPLACE_WITH_NEW_')
}

function buildUnresolvedOutputPath(outputPath) {
  const parsedPath = path.parse(outputPath)
  return path.join(parsedPath.dir, `${parsedPath.name}.unresolved.json`)
}

async function writeSensitiveFile(filePath, content) {
  await writeFile(filePath, content, {
    encoding: 'utf8',
    mode: SENSITIVE_FILE_MODE,
  })

  try {
    await chmod(filePath, SENSITIVE_FILE_MODE)
  } catch (error) {
    warn(
      `Unable to enforce restrictive file permissions on ${filePath}: ` +
      `${error instanceof Error ? error.message : String(error)}`,
    )
  }
}

function getToken() {
  for (const envName of DEFAULT_TOKEN_ENV_NAMES) {
    const value = process.env[envName]

    if (value) {
      return value
    }
  }

  fail(`Missing Vercel token. Set one of: ${DEFAULT_TOKEN_ENV_NAMES.join(', ')}`)
}

function getTeamQuery(options) {
  const query = new URLSearchParams()

  if (options.teamId && options.teamSlug) {
    fail('Pass either --team-id or --team-slug, not both.')
  }

  if (options.teamId) {
    query.set('teamId', options.teamId)
  }

  if (options.teamSlug) {
    query.set('slug', options.teamSlug)
  }

  return query
}

async function vercelRequest({ method, path, token, query, body }) {
  const url = new URL(`${API_BASE_URL}${path}`)

  if (query) {
    const searchParams = query instanceof URLSearchParams
      ? query
      : new URLSearchParams(query)

    for (const [key, value] of searchParams.entries()) {
      url.searchParams.set(key, value)
    }
  }

  for (let retryCount = 0; retryCount <= MAX_REQUEST_RETRIES; retryCount += 1) {
    let response

    try {
      response = await fetch(url, {
        method,
        headers: {
          Authorization: `Bearer ${token}`,
          ...(body ? { 'Content-Type': 'application/json' } : {}),
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
      })
    } catch (error) {
      if (!shouldRetryNetworkError(error) || retryCount >= MAX_REQUEST_RETRIES) {
        throw error
      }

      const retryDelayMs = getRetryDelayMs(retryCount + 1)
      warn(
        `Request ${method} ${url.pathname} failed due to network error, retrying ` +
        `(${retryCount + 1}/${MAX_REQUEST_RETRIES}) in ${retryDelayMs}ms...`,
      )
      await wait(retryDelayMs)
      continue
    }

    const text = await response.text()
    const payload = text ? safeJsonParse(text) : null

    if (!response.ok) {
      const details = typeof payload === 'object' && payload !== null
        ? JSON.stringify(payload)
        : text

      if (!shouldRetryStatusCode(response.status) || retryCount >= MAX_REQUEST_RETRIES) {
        throw new Error(`${method} ${url.pathname} failed (${response.status}): ${details}`)
      }

      const retryDelayMs = getRetryDelayMs(retryCount + 1)
      warn(
        `Request ${method} ${url.pathname} failed (${response.status}), retrying ` +
        `(${retryCount + 1}/${MAX_REQUEST_RETRIES}) in ${retryDelayMs}ms...`,
      )
      await wait(retryDelayMs)
      continue
    }

    return payload
  }

  throw new Error(`Unexpected request retry exhaustion for ${method} ${url.pathname}.`)
}

function shouldRetryStatusCode(statusCode) {
  return statusCode === 429 || statusCode >= 500
}

function shouldRetryNetworkError(error) {
  if (!(error instanceof Error)) {
    return false
  }

  const message = error.message.toLowerCase()

  return message.includes('fetch failed')
    || message.includes('network')
    || message.includes('timeout')
    || message.includes('socket')
    || message.includes('econnreset')
    || message.includes('enotfound')
    || message.includes('eai_again')
}

function getRetryDelayMs(retryAttempt) {
  const exponentialDelay = RETRY_BASE_DELAY_MS * (2 ** (retryAttempt - 1))
  const clampedDelay = Math.min(RETRY_MAX_DELAY_MS, exponentialDelay)
  const jitter = Math.floor(Math.random() * 250)

  return clampedDelay + jitter
}

function safeJsonParse(text) {
  try {
    return JSON.parse(text)
  } catch {
    return text
  }
}

async function readManifest(manifestPath) {
  const raw = await readFile(manifestPath, 'utf8')
  const parsed = JSON.parse(raw)

  if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.entries)) {
    fail(`Manifest at ${manifestPath} must contain an "entries" array.`)
  }

  const entries = new Map()

  for (const entry of parsed.entries) {
    if (!entry || typeof entry !== 'object') {
      fail('Each manifest entry must be an object.')
    }

    const key = typeof entry.key === 'string' ? entry.key.trim() : ''

    if (!key) {
      fail('Each manifest entry must include a non-empty "key".')
    }

    if (entries.has(key)) {
      fail(`Manifest contains duplicate key "${key}".`)
    }

    entries.set(key, {
      key,
      all: isRecordEmpty(entry.all) ? undefined : String(entry.all),
      production: isRecordEmpty(entry.production) ? undefined : String(entry.production),
      preview: isRecordEmpty(entry.preview) ? undefined : String(entry.preview),
      comment: isRecordEmpty(entry.comment) ? undefined : String(entry.comment),
    })
  }

  return entries
}

function collectEnvList(payload, key) {
  if (Array.isArray(payload)) {
    return payload
  }

  if (payload && Array.isArray(payload[key])) {
    return payload[key]
  }

  return []
}

async function listProjectEnvVars({ token, project, teamQuery }) {
  return listProjectEnvVarsInternal({
    token,
    project,
    teamQuery,
    decrypt: false,
  })
}

async function listProjectEnvVarsInternal({ token, project, teamQuery, decrypt }) {
  const query = new URLSearchParams(teamQuery)

  if (decrypt) {
    query.set('decrypt', 'true')
    // Vercel currently returns ciphertext blobs for many encrypted vars unless
    // the request mimics the CLI env-pull code path.
    query.set('source', 'vercel-cli:pull')
  }

  const payload = await vercelRequest({
    method: 'GET',
    path: `/v10/projects/${encodeURIComponent(project)}/env`,
    token,
    query,
  })

  return collectEnvList(payload, 'envs')
}

async function getProjectEnvVarById({ token, project, teamQuery, envVarId }) {
  return vercelRequest({
    method: 'GET',
    path: `/v1/projects/${encodeURIComponent(project)}/env/${encodeURIComponent(envVarId)}`,
    token,
    query: teamQuery,
  })
}

async function listSharedEnvVars({ token, teamQuery, project }) {
  const query = new URLSearchParams(teamQuery)

  if (project) {
    query.set('projectId', project)
  }

  const payload = await vercelRequest({
    method: 'GET',
    path: '/v1/env',
    token,
    query,
  })

  return collectEnvList(payload, 'data')
}

function buildRotationState(remoteEnvVars, options) {
  const byKey = new Map()

  for (const envVar of remoteEnvVars) {
    if (!envVar || typeof envVar.key !== 'string') {
      continue
    }

    if (!options.allowGitBranchVars && isGitBranchScoped(envVar)) {
      continue
    }

    if (!byKey.has(envVar.key)) {
      byKey.set(envVar.key, [])
    }

    byKey.get(envVar.key).push(envVar)
  }

  return byKey
}

function isExportableEnvVar(envVar) {
  return envVar.type !== 'sensitive' && envVar.type !== 'system'
}

async function hydrateProjectExportValues({ token, project, teamQuery, remoteEnvVars }) {
  return Promise.all(remoteEnvVars.map(async (envVar) => {
    if (!isExportableEnvVar(envVar) || hasReadablePlaintextValue(envVar) || !envVar.id) {
      return envVar
    }

    try {
      const byId = await getProjectEnvVarById({
        token,
        project,
        teamQuery,
        envVarId: envVar.id,
      })

      return {
        ...envVar,
        ...byId,
      }
    } catch (error) {
      warn(
        `Unable to fetch decrypted-by-id value for "${envVar.key}" (${envVar.id}): ` +
        `${error instanceof Error ? error.message : String(error)}`,
      )
      return envVar
    }
  }))
}

function buildPlan({ manifestEntries, remoteByKey, includeKeys, excludeKeys }) {
  const plan = []

  for (const [key, manifestEntry] of manifestEntries.entries()) {
    if (includeKeys.size > 0 && !includeKeys.has(key)) {
      continue
    }

    if (excludeKeys.has(key)) {
      continue
    }

    const currentEnvVars = remoteByKey.get(key) ?? []

    if (currentEnvVars.length === 0) {
      fail(`No current Vercel env vars found for "${key}".`)
    }

    const phases = []

    for (const phase of PHASES) {
      const matches = currentEnvVars.filter(envVar => appliesToTarget(envVar, phase))

      if (matches.length > 1) {
        fail(
          `Key "${key}" has ${matches.length} overlapping records for ${phase}. ` +
          'Clean that up manually first so rotation is deterministic.',
        )
      }

      if (matches.length === 0) {
        continue
      }

      const existing = matches[0]
      const replacementValue = manifestEntry[phase] ?? manifestEntry.all

      if (!replacementValue) {
        warn(`Skipping "${key}" for ${phase} because the manifest does not provide a replacement value.`)
        continue
      }

      if (looksLikeVercelCiphertext(replacementValue)) {
        fail(
          `Manifest entry "${key}" for ${phase} still contains a Vercel ciphertext blob. ` +
          'Replace it with the real new secret value before running rotation.',
        )
      }

      if (isGeneratedPlaceholder(replacementValue)) {
        fail(
          `Manifest entry "${key}" for ${phase} still contains a generated placeholder. ` +
          'Replace it with the real new secret value before running rotation.',
        )
      }

      phases.push({
        phase,
        existing,
        replacementValue,
      })
    }

    if (phases.length === 0) {
      warn(`Skipping "${key}" because it is not currently targeted to production or preview.`)
      continue
    }

    plan.push({
      key,
      manifestEntry,
      phases,
    })
  }

  if (plan.length === 0) {
    fail('No keys matched after applying include/exclude filters.')
  }

  return plan
}

function getRemainingTargets(existing, phase) {
  return normalizeTargets(existing.target).filter(target => target !== phase)
}

function sameStringArray(left, right) {
  if (left.length !== right.length) {
    return false
  }

  return left.every((value, index) => value === right[index])
}

function uniqueSorted(values) {
  return [...new Set(values)].sort()
}

function normalizeSharedProjectIds(value) {
  if (value === undefined || value === null) {
    return []
  }

  if (typeof value === 'string') {
    const trimmed = value.trim()
    return trimmed ? [trimmed] : []
  }

  if (Array.isArray(value)) {
    return uniqueSorted(value.flatMap(item => normalizeSharedProjectIds(item)))
  }

  if (typeof value === 'object') {
    const maybeId = typeof value.id === 'string'
      ? value.id
      : typeof value.projectId === 'string'
        ? value.projectId
        : ''
    const trimmed = maybeId.trim()

    return trimmed ? [trimmed] : []
  }

  return []
}

function resolveSharedProjectBinding(existing, key) {
  const bindingCandidates = [
    { field: 'projectId', value: existing.projectId },
    { field: 'projectIds', value: existing.projectIds },
    { field: 'projects', value: existing.projects },
  ].filter(candidate => candidate.value !== undefined && candidate.value !== null)

  if (bindingCandidates.length === 0) {
    return {
      hasBinding: false,
      projectIds: [],
    }
  }

  const normalizedByField = bindingCandidates.map(candidate => ({
    field: candidate.field,
    projectIds: normalizeSharedProjectIds(candidate.value),
  }))
  const nonEmpty = normalizedByField.filter(candidate => candidate.projectIds.length > 0)

  if (nonEmpty.length === 0) {
    fail(
      `Unable to preserve shared project binding for "${key}" ` +
      `(${existing.id ?? 'unknown-id'}). Existing binding fields ` +
      `(${bindingCandidates.map(candidate => candidate.field).join(', ')}) ` +
      'did not contain parseable project ids.',
    )
  }

  const baseline = nonEmpty[0].projectIds

  for (const candidate of nonEmpty.slice(1)) {
    if (!sameStringArray(candidate.projectIds, baseline)) {
      fail(
        `Inconsistent shared project binding metadata for "${key}" ` +
        `(${existing.id ?? 'unknown-id'}). Refusing to rotate automatically.`,
      )
    }
  }

  return {
    hasBinding: true,
    projectIds: baseline,
  }
}

function setToSortedArray(set) {
  return uniqueSorted([...set])
}

function buildPlanSteps(plan) {
  const steps = []

  for (const phase of PHASES) {
    for (const item of plan) {
      const phaseState = item.phases.find(candidate => candidate.phase === phase)

      if (!phaseState) {
        continue
      }

      steps.push({
        key: item.key,
        phase,
      })
    }
  }

  return steps
}

function buildPlanStepId(step) {
  return `${step.phase}::${step.key}`
}

function normalizeJournalStepList(stepList, listName, journalPath) {
  if (!Array.isArray(stepList)) {
    fail(`Journal at ${journalPath} has invalid "${listName}" (expected array).`)
  }

  return stepList.map((step, index) => {
    if (!step || typeof step !== 'object') {
      fail(`Journal at ${journalPath} has invalid ${listName}[${index}] entry.`)
    }

    if (typeof step.key !== 'string' || !step.key.trim()) {
      fail(`Journal at ${journalPath} has invalid ${listName}[${index}].key.`)
    }

    if (!PHASES.includes(step.phase)) {
      fail(`Journal at ${journalPath} has invalid ${listName}[${index}].phase.`)
    }

    return {
      key: step.key,
      phase: step.phase,
    }
  })
}

function createNewJournal({
  scope,
  project,
  teamId,
  teamSlug,
  manifestPath,
  allowGitBranchVars,
  include,
  exclude,
  planSteps,
}) {
  const now = new Date().toISOString()

  return {
    version: JOURNAL_VERSION,
    status: 'running',
    createdAt: now,
    updatedAt: now,
    scope,
    project: project ?? null,
    teamId: teamId ?? null,
    teamSlug: teamSlug ?? null,
    manifestPath,
    allowGitBranchVars,
    include,
    exclude,
    planSteps,
    completedSteps: [],
    lastError: null,
  }
}

async function readJournalFile(journalPath) {
  try {
    const raw = await readFile(journalPath, 'utf8')
    return JSON.parse(raw)
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
      return null
    }

    fail(
      `Unable to read journal at ${journalPath}: ` +
      `${error instanceof Error ? error.message : String(error)}`,
    )
  }
}

async function writeJournalFile(journalPath, journal) {
  await writeSensitiveFile(journalPath, `${JSON.stringify(journal, null, 2)}\n`)
}

function validateResumeJournal({
  journal,
  journalPath,
  scope,
  project,
  teamId,
  teamSlug,
  manifestPath,
  allowGitBranchVars,
  include,
  exclude,
  planSteps,
}) {
  if (!journal || typeof journal !== 'object') {
    fail(`Journal at ${journalPath} is invalid.`)
  }

  if (journal.version !== JOURNAL_VERSION) {
    fail(`Journal at ${journalPath} has unsupported version "${journal.version}".`)
  }

  const expected = {
    scope,
    project: project ?? null,
    teamId: teamId ?? null,
    teamSlug: teamSlug ?? null,
    manifestPath,
    allowGitBranchVars,
    include,
    exclude,
  }

  const actual = {
    scope: journal.scope,
    project: journal.project ?? null,
    teamId: journal.teamId ?? null,
    teamSlug: journal.teamSlug ?? null,
    manifestPath: journal.manifestPath,
    allowGitBranchVars: Boolean(journal.allowGitBranchVars),
    include: Array.isArray(journal.include) ? uniqueSorted(journal.include) : null,
    exclude: Array.isArray(journal.exclude) ? uniqueSorted(journal.exclude) : null,
  }

  if (
    actual.scope !== expected.scope
    || actual.project !== expected.project
    || actual.teamId !== expected.teamId
    || actual.teamSlug !== expected.teamSlug
    || actual.manifestPath !== expected.manifestPath
    || actual.allowGitBranchVars !== expected.allowGitBranchVars
  ) {
    fail(
      `Journal at ${journalPath} does not match this run's scope/project/team/manifest settings. ` +
      'Use the exact same arguments to resume.',
    )
  }

  if (!actual.include || !sameStringArray(actual.include, expected.include)) {
    fail(
      `Journal at ${journalPath} does not match this run's --include filter. ` +
      'Use the exact same arguments to resume.',
    )
  }

  if (!actual.exclude || !sameStringArray(actual.exclude, expected.exclude)) {
    fail(
      `Journal at ${journalPath} does not match this run's --exclude filter. ` +
      'Use the exact same arguments to resume.',
    )
  }

  const journalPlanSteps = normalizeJournalStepList(journal.planSteps, 'planSteps', journalPath)
  const currentPlanStepIds = planSteps.map(step => buildPlanStepId(step))
  const journalPlanStepIds = journalPlanSteps.map(step => buildPlanStepId(step))

  if (!sameStringArray(journalPlanStepIds, currentPlanStepIds)) {
    fail(
      `Journal at ${journalPath} does not match the current rotation plan. ` +
      'If the manifest or remote state changed, start a new non-resume run.',
    )
  }

  const completedSteps = normalizeJournalStepList(
    Array.isArray(journal.completedSteps) ? journal.completedSteps : [],
    'completedSteps',
    journalPath,
  )
  const planStepIdSet = new Set(currentPlanStepIds)
  const completedStepIds = new Set()

  for (const step of completedSteps) {
    const stepId = buildPlanStepId(step)

    if (!planStepIdSet.has(stepId)) {
      fail(
        `Journal at ${journalPath} contains completed step ${step.phase}/${step.key} ` +
        'that is not part of the current plan.',
      )
    }

    completedStepIds.add(stepId)
  }

  if (journal.status === 'completed' && completedStepIds.size === currentPlanStepIds.length) {
    fail(`Journal at ${journalPath} is already marked completed.`)
  }

  return {
    journal: {
      ...journal,
      status: 'running',
      updatedAt: new Date().toISOString(),
      lastError: null,
      planSteps: journalPlanSteps,
      completedSteps,
    },
    completedStepIds,
  }
}

function buildNonSensitiveManifest({ remoteByKey, includeKeys, excludeKeys }) {
  const entries = []
  const unresolved = []

  for (const [key, envVars] of [...remoteByKey.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    if (includeKeys.size > 0 && !includeKeys.has(key)) {
      continue
    }

    if (excludeKeys.has(key)) {
      continue
    }

    const exportable = envVars.filter(isExportableEnvVar)

    if (exportable.length === 0) {
      continue
    }

    const phaseValues = {}
    const comments = new Set()

    for (const phase of PHASES) {
      const matches = exportable.filter(envVar => appliesToTarget(envVar, phase))

      if (matches.length > 1) {
        fail(
          `Key "${key}" has ${matches.length} non-sensitive records for ${phase}. ` +
          'Clean that up manually first so the exported manifest is deterministic.',
        )
      }

      const match = matches[0]

      if (!match) {
        continue
      }

      if (!hasReadablePlaintextValue(match)) {
        phaseValues[phase] = buildPlaceholderValue({ key, phase })
        unresolved.push({
          key,
          phase,
          id: match.id,
          type: match.type,
          reason: looksLikeVercelCiphertext(match.value)
            ? 'vercel_returned_ciphertext'
            : 'vercel_did_not_return_plaintext',
        })
      } else {
        phaseValues[phase] = match.value
      }

      if (match.comment) {
        comments.add(match.comment)
      }
    }

    if (!phaseValues.production && !phaseValues.preview) {
      continue
    }

    const entry = { key }

    if (phaseValues.production && phaseValues.preview && phaseValues.production === phaseValues.preview) {
      entry.all = phaseValues.production
    } else {
      if (phaseValues.production) {
        entry.production = phaseValues.production
      }

      if (phaseValues.preview) {
        entry.preview = phaseValues.preview
      }
    }

    if (comments.size === 1) {
      entry.comment = [...comments][0]
    }

    entries.push(entry)
  }

  return { entries, unresolved }
}

async function dumpNonSensitiveManifest({
  scope,
  token,
  project,
  teamQuery,
  includeKeys,
  excludeKeys,
  allowGitBranchVars,
  outputPath,
}) {
  info(`Loading current ${scope} environment variables from Vercel...`)

  const remoteEnvVars = scope === 'project'
    ? await listProjectEnvVarsInternal({
      token,
      project,
      teamQuery,
      decrypt: true,
    })
    : await listSharedEnvVars({
      token,
      teamQuery,
      project,
    })
  const hydratedRemoteEnvVars = scope === 'project'
    ? await hydrateProjectExportValues({
      token,
      project,
      teamQuery,
      remoteEnvVars,
    })
    : remoteEnvVars

  const remoteByKey = buildRotationState(hydratedRemoteEnvVars, {
    allowGitBranchVars,
  })
  const manifest = buildNonSensitiveManifest({
    remoteByKey,
    includeKeys,
    excludeKeys,
  })
  const manifestJson = `${JSON.stringify({ entries: manifest.entries }, null, 2)}\n`

  if (outputPath) {
    await writeSensitiveFile(outputPath, manifestJson)
    info(`Wrote non-sensitive manifest to ${outputPath}`)
    if (manifest.unresolved.length > 0) {
      const unresolvedOutputPath = buildUnresolvedOutputPath(outputPath)
      await writeSensitiveFile(
        unresolvedOutputPath,
        `${JSON.stringify({ unresolved: manifest.unresolved }, null, 2)}\n`,
      )
      info(`Wrote unresolved export report to ${unresolvedOutputPath}`)
      warn(
        `${manifest.unresolved.length} values could not be exported as plaintext. ` +
        'The manifest contains REPLACE_WITH_NEW_* placeholders that must be filled in manually.',
      )
    }
    return
  }

  process.stdout.write(manifestJson)
  if (manifest.unresolved.length > 0) {
    warn(
      `${manifest.unresolved.length} values could not be exported as plaintext. ` +
      'Re-run with --output to also write a separate .unresolved.json report.',
    )
  }
}

function describePhaseAction({ key, phase, existing }) {
  const existingTargets = normalizeTargets(existing.target).join(',')
  const existingType = existing.type ?? 'unknown'
  const splitNote = normalizeTargets(existing.target).length > 1
    ? `split existing targets [${existingTargets}]`
    : `replace existing [${existingTargets}]`

  return `- ${key} (${phase}): ${splitNote}, recreate as sensitive (was ${existingType})`
}

async function patchProjectEnvTarget({ token, project, teamQuery, envVarId, target }) {
  await vercelRequest({
    method: 'PATCH',
    path: `/v9/projects/${encodeURIComponent(project)}/env/${encodeURIComponent(envVarId)}`,
    token,
    query: teamQuery,
    body: { target },
  })
}

async function deleteProjectEnv({ token, project, teamQuery, envVarId }) {
  await vercelRequest({
    method: 'DELETE',
    path: `/v9/projects/${encodeURIComponent(project)}/env/${encodeURIComponent(envVarId)}`,
    token,
    query: teamQuery,
  })
}

async function createProjectSensitiveEnv({
  token,
  project,
  teamQuery,
  key,
  value,
  phase,
  comment,
}) {
  await vercelRequest({
    method: 'POST',
    path: `/v10/projects/${encodeURIComponent(project)}/env`,
    token,
    query: teamQuery,
    body: [
      {
        key,
        value,
        type: 'sensitive',
        target: [phase],
        ...(comment ? { comment } : {}),
      },
    ],
  })
}

async function patchSharedEnvTarget({ token, teamQuery, envVarId, target }) {
  const payload = await vercelRequest({
    method: 'PATCH',
    path: '/v1/env',
    token,
    query: teamQuery,
    body: {
      updates: {
        [envVarId]: { target },
      },
    },
  })

  if (payload?.failed?.length) {
    throw new Error(`Shared env PATCH failed: ${JSON.stringify(payload.failed)}`)
  }
}

async function deleteSharedEnv({ token, teamQuery, envVarId }) {
  const payload = await vercelRequest({
    method: 'DELETE',
    path: '/v1/env',
    token,
    query: teamQuery,
    body: { ids: [envVarId] },
  })

  if (payload?.failed?.length) {
    throw new Error(`Shared env DELETE failed: ${JSON.stringify(payload.failed)}`)
  }
}

async function createSharedSensitiveEnv({
  token,
  teamQuery,
  key,
  value,
  phase,
  comment,
  projectIds,
}) {
  const payload = await vercelRequest({
    method: 'POST',
    path: '/v1/env',
    token,
    query: teamQuery,
    body: {
      evs: [
        {
          key,
          value,
          ...(comment ? { comment } : {}),
        },
      ],
      type: 'sensitive',
      target: [phase],
      ...(Array.isArray(projectIds) && projectIds.length > 0 ? { projectId: projectIds } : {}),
    },
  })

  if (payload?.failed?.length) {
    throw new Error(`Shared env CREATE failed: ${JSON.stringify(payload.failed)}`)
  }
}

async function rotatePhase({ scope, token, project, teamQuery, key, manifestEntry, phaseState }) {
  const { phase, existing, replacementValue } = phaseState
  const remainingTargets = getRemainingTargets(existing, phase)
  const comment = manifestEntry.comment ?? existing.comment
  const sharedBinding = scope === 'shared'
    ? resolveSharedProjectBinding(existing, key)
    : null

  info(`Rotating ${key} for ${phase}...`)

  if (scope === 'project') {
    if (remainingTargets.length > 0) {
      await patchProjectEnvTarget({
        token,
        project,
        teamQuery,
        envVarId: existing.id,
        target: remainingTargets,
      })
      existing.target = remainingTargets
    } else {
      await deleteProjectEnv({
        token,
        project,
        teamQuery,
        envVarId: existing.id,
      })
      existing.target = []
    }

    await createProjectSensitiveEnv({
      token,
      project,
      teamQuery,
      key,
      value: replacementValue,
      phase,
      comment,
    })

    return
  }

  if (remainingTargets.length > 0) {
    await patchSharedEnvTarget({
      token,
      teamQuery,
      envVarId: existing.id,
      target: remainingTargets,
    })
    existing.target = remainingTargets
  } else {
    await deleteSharedEnv({
      token,
      teamQuery,
      envVarId: existing.id,
    })
    existing.target = []
  }

  await createSharedSensitiveEnv({
    token,
    teamQuery,
    key,
    value: replacementValue,
    phase,
    comment,
    projectIds: sharedBinding?.hasBinding ? sharedBinding.projectIds : undefined,
  })
}

function verifyPlanAgainstRemote(plan, remoteByKey) {
  for (const item of plan) {
    const currentEnvVars = remoteByKey.get(item.key) ?? []

    for (const phaseState of item.phases) {
      const matches = currentEnvVars.filter(envVar => appliesToTarget(envVar, phaseState.phase))

      if (matches.length !== 1) {
        fail(`Verification failed for "${item.key}" in ${phaseState.phase}: expected exactly one record.`)
      }

      const match = matches[0]

      if (match.type !== 'sensitive') {
        fail(`Verification failed for "${item.key}" in ${phaseState.phase}: type is ${match.type}, expected sensitive.`)
      }
    }
  }
}

async function main() {
  const { values } = parseArgs({
    options: {
      help: { type: 'boolean', short: 'h' },
      scope: { type: 'string' },
      project: { type: 'string' },
      manifest: { type: 'string' },
      'team-id': { type: 'string' },
      'team-slug': { type: 'string' },
      include: { type: 'string' },
      exclude: { type: 'string' },
      yes: { type: 'boolean' },
      resume: { type: 'boolean' },
      journal: { type: 'string' },
      'allow-git-branch-vars': { type: 'boolean' },
      'dump-non-sensitive-manifest': { type: 'boolean' },
      output: { type: 'string' },
    },
    allowPositionals: false,
  })

  if (values.help) {
    printHelp()
    return
  }

  const scope = values.scope

  if (scope !== 'project' && scope !== 'shared') {
    fail('Pass --scope project or --scope shared.')
  }

  if (scope === 'project' && !values.project) {
    fail('Project scope requires --project <project-id-or-name>.')
  }

  const token = getToken()
  const teamQuery = getTeamQuery({
    teamId: values['team-id'],
    teamSlug: values['team-slug'],
  })
  const includeKeys = parseCommaList(values.include)
  const excludeKeys = parseCommaList(values.exclude)
  const allowGitBranchVars = Boolean(values['allow-git-branch-vars'])
  const shouldResume = Boolean(values.resume)
  const journalPath = path.resolve(values.journal ?? DEFAULT_JOURNAL_FILENAME)

  if (shouldResume && !values.yes) {
    fail('--resume requires --yes.')
  }

  if (values['dump-non-sensitive-manifest'] && shouldResume) {
    fail('--resume is only supported in rotation mode (without --dump-non-sensitive-manifest).')
  }

  if (values['dump-non-sensitive-manifest']) {
    await dumpNonSensitiveManifest({
      scope,
      token,
      project: values.project,
      teamQuery,
      includeKeys,
      excludeKeys,
      allowGitBranchVars,
      outputPath: values.output,
    })
    return
  }

  if (!values.manifest) {
    fail('Pass --manifest with a JSON manifest file.')
  }

  const manifestPath = path.resolve(values.manifest)

  const manifestEntries = await readManifest(manifestPath)

  info(`Loading current ${scope} environment variables from Vercel...`)

  const remoteEnvVars = scope === 'project'
    ? await listProjectEnvVars({
      token,
      project: values.project,
      teamQuery,
    })
    : await listSharedEnvVars({
      token,
      teamQuery,
      project: values.project,
    })

  const remoteByKey = buildRotationState(remoteEnvVars, {
    allowGitBranchVars,
  })
  const plan = buildPlan({
    manifestEntries,
    remoteByKey,
    includeKeys,
    excludeKeys,
  })

  info('')
  info('Planned rotation:')

  for (const item of plan) {
    for (const phaseState of item.phases) {
      info(describePhaseAction({
        key: item.key,
        phase: phaseState.phase,
        existing: phaseState.existing,
      }))
    }
  }

  if (!values.yes) {
    info('')
    info('Plan only. Re-run with --yes to perform the rotation.')
    return
  }

  const planSteps = buildPlanSteps(plan)
  const include = setToSortedArray(includeKeys)
  const exclude = setToSortedArray(excludeKeys)
  let journal
  let completedStepIds

  if (shouldResume) {
    const loadedJournal = await readJournalFile(journalPath)

    if (!loadedJournal) {
      fail(
        `No journal file found at ${journalPath}. ` +
        'Start a non-resume run first, then use --resume if an apply is interrupted.',
      )
    }

    const resumeState = validateResumeJournal({
      journal: loadedJournal,
      journalPath,
      scope,
      project: values.project,
      teamId: values['team-id'],
      teamSlug: values['team-slug'],
      manifestPath,
      allowGitBranchVars,
      include,
      exclude,
      planSteps,
    })

    journal = resumeState.journal
    completedStepIds = resumeState.completedStepIds
    await writeJournalFile(journalPath, journal)
    info(
      `Resuming from journal ${journalPath}. ` +
      `${completedStepIds.size}/${planSteps.length} steps are already complete.`,
    )
  } else {
    journal = createNewJournal({
      scope,
      project: values.project,
      teamId: values['team-id'],
      teamSlug: values['team-slug'],
      manifestPath,
      allowGitBranchVars,
      include,
      exclude,
      planSteps,
    })
    completedStepIds = new Set()
    await writeJournalFile(journalPath, journal)
    info(`Created rotation journal at ${journalPath}.`)
  }

  try {
    info('')
    info('Applying rotation in order: production, then preview.')

    for (const phase of PHASES) {
      info('')
      info(`=== ${phase.toUpperCase()} ===`)

      for (const item of plan) {
        const phaseState = item.phases.find(candidate => candidate.phase === phase)

        if (!phaseState) {
          continue
        }

        const stepId = buildPlanStepId({
          key: item.key,
          phase,
        })

        if (completedStepIds.has(stepId)) {
          info(`Skipping ${item.key} for ${phase}; already completed in journal.`)
          continue
        }

        await rotatePhase({
          scope,
          token,
          project: values.project,
          teamQuery,
          key: item.key,
          manifestEntry: item.manifestEntry,
          phaseState,
        })

        completedStepIds.add(stepId)
        journal.completedSteps.push({
          key: item.key,
          phase,
          completedAt: new Date().toISOString(),
        })
        journal.updatedAt = new Date().toISOString()
        await writeJournalFile(journalPath, journal)
      }
    }

    info('')
    info('Verifying final state...')

    const finalRemoteEnvVars = scope === 'project'
      ? await listProjectEnvVars({
        token,
        project: values.project,
        teamQuery,
      })
      : await listSharedEnvVars({
        token,
        teamQuery,
        project: values.project,
      })

    const finalRemoteByKey = buildRotationState(finalRemoteEnvVars, {
      allowGitBranchVars,
    })

    verifyPlanAgainstRemote(plan, finalRemoteByKey)

    journal.status = 'completed'
    journal.updatedAt = new Date().toISOString()
    journal.lastError = null
    await writeJournalFile(journalPath, journal)

    info('Rotation complete. All rotated production/preview variables now verify as sensitive.')
    info(`Journal saved at ${journalPath}.`)
  } catch (error) {
    journal.status = 'failed'
    journal.updatedAt = new Date().toISOString()
    journal.lastError = error instanceof Error ? error.message : String(error)

    try {
      await writeJournalFile(journalPath, journal)
    } catch (journalError) {
      warn(
        `Unable to persist failed-run journal at ${journalPath}: ` +
        `${journalError instanceof Error ? journalError.message : String(journalError)}`,
      )
    }

    warn(
      `Rotation interrupted. Re-run with the same command plus --resume --journal ${journalPath} ` +
      'to continue from the last completed step.',
    )
    throw error
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error)
  process.exit(1)
})
