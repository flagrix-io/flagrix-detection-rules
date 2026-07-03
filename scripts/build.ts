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
  description?: string
}

interface YaraRule {
  id: string
  name: string
  pattern: string
  description: string
  tags: string[]
  severity: string
}

interface KnownBadHash {
  sha256: string
  type: string
  malwareFamily?: string
  source: string
  description?: string
}

interface SignatureDatabase {
  version: string
  lastUpdated: string
  maliciousPackages: MaliciousPackage[]
  yaraRules: YaraRule[]
  knownBadHashes: KnownBadHash[]
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

  const db: SignatureDatabase = {
    version: buildVersion(),
    lastUpdated: new Date().toISOString(),
    maliciousPackages,
    yaraRules,
    knownBadHashes,
  }

  const outputPath = join(ROOT, "signatures.json")
  writeFileSync(outputPath, JSON.stringify(db, null, 2), "utf8")

  console.log(`\nBuild complete: signatures.json`)
  console.log(`  Version: ${db.version}`)
  console.log(`  Packages: ${maliciousPackages.length}`)
  console.log(`  YARA rules: ${yaraRules.length}`)
  console.log(`  Bad hashes: ${knownBadHashes.length}`)
}

build()
