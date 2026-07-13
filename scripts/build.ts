/**
 * Build Script — Flagrix Detection Rules
 *
 * Compiles all YAML rule files into a single signatures.json file
 * in the format the Flagrix extension expects (SignatureDatabase).
 *
 * Usage: npm run build
 * Output: signatures.json
 */

import { readFileSync, writeFileSync } from "node:fs"
import { join, dirname } from "node:path"
import { fileURLToPath } from "node:url"
import yaml from "js-yaml"

const __dirname = dirname(fileURLToPath(import.meta.url))
const ROOT = join(__dirname, "..")

function loadYaml<T>(relPath: string): T {
  const content = readFileSync(join(ROOT, relPath), "utf8")
  return yaml.load(content) as T
}

interface MaliciousPackage {
  name: string
  severity: string
  source: string
  version?: string
  versions?: string[]
  description?: string
}

interface YaraRule {
  id: string
  name: string
  pattern: string
  description: string
  tags: string[]
  severity: string
  confidence?: "high" | "medium" | "low"
  context?: "keyboard-capture"
  /** Minimum regex matches in one file before the rule fires (default 1). */
  minMatches?: number
  /** Restrict the rule to these file extensions (default: all scannable). */
  fileExtensions?: string[]
  /** Restrict the rule to exact file basenames. */
  fileNames?: string[]
}

interface KnownBadHash {
  sha256: string
  type: string
  malwareFamily?: string
  source: string
  description?: string
}

interface ProfileSimpleCondition {
  field: string
  operator: string
  value: number | boolean
}
interface ProfileCondition {
  all?: ProfileSimpleCondition[]
  field?: string
  operator?: string
  value?: number | boolean
}
interface ProfileRiskRule {
  id: string
  name: string
  description: string
  weight: number
  condition: ProfileCondition
  exclusiveWith?: string
}
interface UserProfileRuleset {
  riskFactors: ProfileRiskRule[]
  trustSignals: ProfileRiskRule[]
  riskLevels: {
    mediumMinScore: number
    highMinScore: number
    recommendations: { low: string; medium: string; high: string }
  }
}

interface SignatureDatabase {
  version: string
  lastUpdated: string
  maliciousPackages: MaliciousPackage[]
  yaraRules: YaraRule[]
  knownBadHashes: KnownBadHash[]
  userProfileRules: UserProfileRuleset
}

// ── Load malicious packages ────────────────────────────────────────────────────

function loadMaliciousPackages(): MaliciousPackage[] {
  const packages: MaliciousPackage[] = []

  const npmData = loadYaml<{ packages: Array<MaliciousPackage & { added?: string; references?: string[]; typosquat_of?: string }> }>(
    "packages/malicious-npm.yaml"
  )
  for (const pkg of npmData.packages) {
    packages.push({
      name: pkg.name,
      severity: pkg.severity,
      source: pkg.source,
      version: pkg.version,
      versions: pkg.versions,
      description: pkg.description,
    })
  }

  const pypiData = loadYaml<{ packages: Array<MaliciousPackage & { added?: string; typosquat_of?: string }> }>(
    "packages/malicious-pypi.yaml"
  )
  for (const pkg of pypiData.packages) {
    packages.push({
      name: pkg.name,
      severity: pkg.severity,
      source: pkg.source,
      description: pkg.description,
    })
  }

  return packages
}

// ── Load YARA rules from repository.yaml ─────────────────────────────────────

interface RawRule {
  id: string
  name: string
  description: string
  severity: string
  confidence?: "high" | "medium" | "low"
  context?: "keyboard-capture"
  tags: string[]
  pattern: {
    type: string
    value?: string
    [key: string]: unknown
  }
}

function extractRegexPattern(rule: RawRule): string | null {
  if (!rule.pattern) return null

  // Only emit rules with a direct regex value (other pattern types are for the scanner engine)
  if (rule.pattern.type === "regex" && rule.pattern.value) {
    return rule.pattern.value as string
  }

  return null
}

function loadYaraRules(): YaraRule[] {
  const rules: YaraRule[] = []

  const repoData = loadYaml<{ rules: RawRule[] }>("rules/github/repository.yaml")
  for (const rule of repoData.rules) {
    const pattern = extractRegexPattern(rule)
    if (pattern) {
      rules.push({
        id: rule.id,
        name: rule.name,
        pattern,
        description: rule.description,
        tags: rule.tags,
        severity: rule.severity,
        ...(rule.confidence ? { confidence: rule.confidence } : {}),
        ...(rule.context ? { context: rule.context } : {}),
        ...(typeof rule.pattern.min_matches === "number" && rule.pattern.min_matches > 1
          ? { minMatches: rule.pattern.min_matches }
          : {}),
        ...(Array.isArray(rule.pattern.file_extensions) && rule.pattern.file_extensions.length > 0
          ? { fileExtensions: rule.pattern.file_extensions as string[] }
          : {}),
        ...(Array.isArray(rule.pattern.file_names) && rule.pattern.file_names.length > 0
          ? { fileNames: rule.pattern.file_names as string[] }
          : {}),
      })
    }
  }

  const obfData = loadYaml<{ rules: RawRule[] }>("rules/github/obfuscation.yaml")
  for (const rule of obfData.rules) {
    const pattern = extractRegexPattern(rule)
    if (pattern) {
      rules.push({
        id: rule.id,
        name: rule.name,
        pattern,
        description: rule.description,
        tags: rule.tags,
        severity: rule.severity,
        ...(rule.confidence ? { confidence: rule.confidence } : {}),
        ...(rule.context ? { context: rule.context } : {}),
        ...(typeof rule.pattern.min_matches === "number" && rule.pattern.min_matches > 1
          ? { minMatches: rule.pattern.min_matches }
          : {}),
        ...(Array.isArray(rule.pattern.file_extensions) && rule.pattern.file_extensions.length > 0
          ? { fileExtensions: rule.pattern.file_extensions as string[] }
          : {}),
        ...(Array.isArray(rule.pattern.file_names) && rule.pattern.file_names.length > 0
          ? { fileNames: rule.pattern.file_names as string[] }
          : {}),
      })
    }
  }

  return rules
}

// ── Load known bad hashes ──────────────────────────────────────────────────────

function loadKnownBadHashes(): KnownBadHash[] {
  const data = loadYaml<{ hashes?: Array<KnownBadHash & { added?: string }> }>(
    "hashes/known-bad.yaml"
  )
  if (!data.hashes) return []

  return data.hashes.map((h) => ({
    sha256: h.sha256,
    type: h.type,
    malwareFamily: h.malwareFamily,
    source: h.source,
    description: h.description,
  }))
}

// ── Load user-profile scoring ruleset ───────────────────────────────────────

// Maps the human-friendly yaml condition `type` names to the camelCase feature
// fields on GitHubUserFeatures that the scanner evaluates.
const PROFILE_FIELD_MAP: Record<string, string> = {
  account_age_days: "accountAgeDays",
  followers: "followers",
  following: "following",
  follower_following_ratio: "followerFollowingRatio",
  owned_repos_count: "ownedReposCount",
  total_stars: "totalStars",
  recent_event_count_90d: "recentEventCount",
  very_recent_event_count_30d: "veryRecentEventCount",
  has_profile_photo: "hasProfilePhoto",
  is_profile_complete: "isProfileComplete",
}

interface RawProfileCondition {
  type: string
  operator?: string
  value?: number | boolean
  conditions?: Array<{ type: string; operator: string; value: number | boolean }>
}
interface RawProfileRule {
  id: string
  name: string
  description: string
  weight: number
  condition: RawProfileCondition
  exclusive_with?: string
}

function mapField(type: string): string {
  const field = PROFILE_FIELD_MAP[type]
  if (!field) throw new Error(`Unknown user-profile condition type: "${type}"`)
  return field
}

function compileCondition(raw: RawProfileCondition): ProfileCondition {
  if (raw.type === "compound") {
    return {
      all: (raw.conditions ?? []).map((c) => ({
        field: mapField(c.type),
        operator: c.operator,
        value: c.value,
      })),
    }
  }
  return { field: mapField(raw.type), operator: raw.operator!, value: raw.value! }
}

function compileRule(raw: RawProfileRule): ProfileRiskRule {
  return {
    id: raw.id,
    name: raw.name,
    description: raw.description,
    weight: raw.weight,
    condition: compileCondition(raw.condition),
    ...(raw.exclusive_with ? { exclusiveWith: raw.exclusive_with } : {}),
  }
}

function loadUserProfileRules(): UserProfileRuleset {
  const data = loadYaml<{
    risk_factors: RawProfileRule[]
    trust_signals: RawProfileRule[]
    risk_levels: {
      low: { max_score: number; recommendation: string }
      medium: { min_score: number; max_score: number; recommendation: string }
      high: { min_score: number; recommendation: string }
    }
  }>("rules/github/user-profile.yaml")

  return {
    riskFactors: data.risk_factors.map(compileRule),
    trustSignals: data.trust_signals.map(compileRule),
    riskLevels: {
      mediumMinScore: data.risk_levels.medium.min_score,
      highMinScore: data.risk_levels.high.min_score,
      recommendations: {
        low: data.risk_levels.low.recommendation,
        medium: data.risk_levels.medium.recommendation,
        high: data.risk_levels.high.recommendation,
      },
    },
  }
}

// ── Determine version ─────────────────────────────────────────────────────────

// The release version is the single source of truth in package.json (format
// YYYY.MM.DD.NNN). Deriving it here keeps signatures.json from ever drifting
// out of sync with the package version. Bump package.json when publishing.
function buildVersion(): string {
  const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"))
  return pkg.version as string
}

// ── Main ──────────────────────────────────────────────────────────────────────

function build(): void {
  console.log("Building signatures.json...")

  const maliciousPackages = loadMaliciousPackages()
  console.log(`  Loaded ${maliciousPackages.length} malicious packages`)

  const yaraRules = loadYaraRules()
  console.log(`  Loaded ${yaraRules.length} YARA rules`)

  const knownBadHashes = loadKnownBadHashes()
  console.log(`  Loaded ${knownBadHashes.length} known bad hashes`)

  const userProfileRules = loadUserProfileRules()
  console.log(
    `  Loaded ${userProfileRules.riskFactors.length} risk factors + ${userProfileRules.trustSignals.length} trust signals`
  )

  const db: SignatureDatabase = {
    version: buildVersion(),
    lastUpdated: new Date().toISOString(),
    maliciousPackages,
    yaraRules,
    knownBadHashes,
    userProfileRules,
  }

  const outputPath = join(ROOT, "signatures.json")
  writeFileSync(outputPath, JSON.stringify(db, null, 2), "utf8")

  console.log(`\nBuild complete: signatures.json`)
  console.log(`  Version: ${db.version}`)
  console.log(`  Packages: ${maliciousPackages.length}`)
  console.log(`  YARA rules: ${yaraRules.length}`)
  console.log(`  Bad hashes: ${knownBadHashes.length}`)
  console.log(
    `  Profile rules: ${userProfileRules.riskFactors.length} risk / ${userProfileRules.trustSignals.length} trust`
  )
}

build()
