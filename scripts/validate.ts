/**
 * Validate Script — Flagrix Detection Rules
 *
 * Validates the compiled signatures.json against the JSON schema.
 * Run after `npm run build`.
 *
 * Usage: npm run validate
 */

import { readFileSync, existsSync } from "node:fs"
import { join, dirname } from "node:path"
import { fileURLToPath } from "node:url"
import Ajv from "ajv"

const __dirname = dirname(fileURLToPath(import.meta.url))
const ROOT = join(__dirname, "..")

function validate(): void {
  const signaturesPath = join(ROOT, "signatures.json")
  const schemaPath = join(ROOT, "schemas", "rule-schema.json")

  if (!existsSync(signaturesPath)) {
    console.error("Error: signatures.json not found. Run `npm run build` first.")
    process.exit(1)
  }

  const signatures = JSON.parse(readFileSync(signaturesPath, "utf8"))
  const schema = JSON.parse(readFileSync(schemaPath, "utf8"))

  const ajv = new Ajv({ allErrors: true, allowUnionTypes: true })
  const validate = ajv.compile(schema)
  const valid = validate(signatures)

  if (!valid) {
    console.error("Validation FAILED:")
    for (const error of validate.errors || []) {
      console.error(`  ${error.instancePath || "/"}: ${error.message}`)
    }
    process.exit(1)
  }

  // Additional checks
  let warnings = 0

  // Check for duplicate rule IDs
  const yaraIds = new Set<string>()
  for (const rule of signatures.yaraRules) {
    if (yaraIds.has(rule.id)) {
      console.warn(`  Warning: Duplicate YARA rule ID: ${rule.id}`)
      warnings++
    }
    yaraIds.add(rule.id)
  }

  // Check for duplicate package names
  const pkgNames = new Set<string>()
  for (const pkg of signatures.maliciousPackages) {
    if (pkgNames.has(pkg.name)) {
      console.warn(`  Warning: Duplicate package name: ${pkg.name}`)
      warnings++
    }
    pkgNames.add(pkg.name)
  }

  // Check for duplicate hashes
  const hashValues = new Set<string>()
  for (const hash of signatures.knownBadHashes) {
    if (hashValues.has(hash.sha256)) {
      console.warn(`  Warning: Duplicate hash: ${hash.sha256.slice(0, 16)}...`)
      warnings++
    }
    hashValues.add(hash.sha256)
  }

  console.log("Validation PASSED")
  console.log(`  Version: ${signatures.version}`)
  console.log(`  Packages: ${signatures.maliciousPackages.length}`)
  console.log(`  YARA rules: ${signatures.yaraRules.length}`)
  console.log(`  Bad hashes: ${signatures.knownBadHashes.length}`)

  if (warnings > 0) {
    console.log(`  ${warnings} warning(s)`)
  }
}

validate()
