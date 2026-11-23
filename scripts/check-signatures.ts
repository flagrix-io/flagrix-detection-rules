/**
 * Checks a freshly built signatures.json against the committed one.
 *
 *   npx tsx scripts/check-signatures.ts <committed.json> <built.json>
 *
 * 1. Every rule pattern compiles the way scanner-core compiles it
 *    (`new RegExp(pattern, "gi")`). The engine skips a rule whose regex throws
 *    without saying so, so a broken pattern would otherwise ship as a rule that
 *    silently never fires.
 * 2. The committed file is what the YAML builds to. `lastUpdated` is a build
 *    timestamp and is ignored; everything else must match, so a rule edit
 *    without a rebuild (or a hand edit of signatures.json) fails here.
 */
import { readFileSync } from "node:fs"

const [committedPath, builtPath] = process.argv.slice(2)
if (!committedPath || !builtPath) {
  console.error("usage: check-signatures.ts <committed.json> <built.json>")
  process.exit(2)
}

type Signatures = { lastUpdated?: string; yaraRules?: Array<{ id: string; pattern: string }> } & Record<string, unknown>
const read = (path: string) => JSON.parse(readFileSync(path, "utf8")) as Signatures
const committed = read(committedPath)
const built = read(builtPath)

const problems: string[] = []

for (const rule of built.yaraRules ?? []) {
  try {
    new RegExp(rule.pattern, "gi")
  } catch (error) {
    problems.push(`${rule.id}: pattern does not compile: ${(error as Error).message}`)
  }
}

const strip = ({ lastUpdated: _, ...rest }: Signatures) => JSON.stringify(rest)
if (strip(committed) !== strip(built)) {
  problems.push(
    "signatures.json is not what the rules build to. Run `npm run build` and commit signatures.json."
  )
}

if (problems.length > 0) {
  for (const problem of problems) console.error(`✗ ${problem}`)
  process.exit(1)
}
console.log(`✓ ${built.yaraRules?.length ?? 0} patterns compile; signatures.json matches the rules`)
