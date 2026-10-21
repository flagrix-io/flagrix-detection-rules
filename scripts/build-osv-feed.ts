/**
 * Build osv-malicious.json — every package the OpenSSF malicious-packages
 * project has confirmed malicious (OSV `MAL-*` records), for npm and PyPI.
 *
 * Usage: tsx scripts/build-osv-feed.ts <npm all.zip> <PyPI all.zip>
 * (the per-ecosystem dumps from https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip)
 *
 * The feed is far too large for signatures.json, which the extension bundles,
 * so it is a separate file that scanners fetch and match locally — dependency
 * names never leave the user's device. Output is deterministic (sorted keys,
 * `updated` = newest record's modified date) so a nightly rebuild only
 * produces a commit when the data changed.
 */
import { execFileSync } from "node:child_process"
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"

/**
 * Per ecosystem: `all` lists packages malicious in every version (almost all
 * of them); `versions` maps the rest to their affected versions. No MAL ids —
 * they would double the size, and a finding links to the osv.dev search for
 * the package instead.
 */
interface EcosystemFeed {
  all: string[]
  versions: Record<string, string[]>
}

interface OsvRecord {
  id: string
  modified?: string
  withdrawn?: string
  affected?: Array<{
    package?: { ecosystem?: string; name?: string }
    versions?: string[]
    ranges?: Array<{ events?: Array<Record<string, string>> }>
  }>
}

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..")
const OUT = join(ROOT, "osv-malicious.json")
// A feed this small means the download or extraction went wrong; never
// publish it over a good one.
const MIN_EXPECTED = { npm: 10_000, pypi: 1_000 }

/** PEP 503 normalisation, so `Foo_Bar` and `foo-bar` match. */
export function normalizePypiName(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, "-")
}

/**
 * "*" when a range is open from 0 (malicious in every version). Otherwise the
 * explicit versions plus each bounded range as a string such as
 * ">=1.0.0 <1.2.11" (fsevents, MAL-2023-462: only 1.x was compromised).
 */
export function affectedVersions(affected: NonNullable<OsvRecord["affected"]>[number]): "*" | string[] {
  const out = new Set(affected.versions ?? [])
  for (const range of affected.ranges ?? []) {
    // null: not inside an affected interval; "": open from 0; ">=x": open from x.
    let lower: string | null = null
    for (const event of range.events ?? []) {
      if ("introduced" in event) {
        lower = event.introduced === "0" ? "" : `>=${event.introduced}`
      } else if (lower !== null) {
        const upper = "fixed" in event || "limit" in event
          ? `<${event.fixed ?? event.limit}`
          : "last_affected" in event ? `<=${event.last_affected}` : null
        if (upper) {
          out.add(lower ? `${lower} ${upper}` : upper)
          lower = null
        }
      }
    }
    if (lower === "") return "*"
    if (lower) out.add(lower)
  }
  return out.size > 0 ? [...out].sort() : "*"
}

function readMalRecords(zipPath: string): OsvRecord[] {
  const dir = mkdtempSync(join(tmpdir(), "osv-"))
  try {
    // Only the MAL-* records: the dump also holds every GHSA/CVE advisory.
    execFileSync("unzip", ["-q", "-o", zipPath, "MAL-*.json", "-d", dir], { stdio: ["ignore", "ignore", "inherit"] })
    return readdirSync(dir).map((file) => JSON.parse(readFileSync(join(dir, file), "utf8")) as OsvRecord)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

export function buildEcosystem(
  records: OsvRecord[],
  ecosystem: "npm" | "PyPI"
): { feed: EcosystemFeed; updated: string } {
  const merged = new Map<string, "*" | Set<string>>()
  let updated = ""
  for (const record of records) {
    if (!record.id?.startsWith("MAL-") || record.withdrawn) continue
    if (record.modified && record.modified > updated) updated = record.modified
    for (const affected of record.affected ?? []) {
      if (affected.package?.ecosystem !== ecosystem || !affected.package.name) continue
      const name = ecosystem === "PyPI" ? normalizePypiName(affected.package.name) : affected.package.name
      const versions = affectedVersions(affected)
      const existing = merged.get(name)
      if (versions === "*" || existing === "*") {
        merged.set(name, "*")
      } else {
        merged.set(name, new Set([...(existing ?? []), ...versions]))
      }
    }
  }
  const feed: EcosystemFeed = { all: [], versions: {} }
  for (const name of [...merged.keys()].sort()) {
    const versions = merged.get(name)!
    if (versions === "*") feed.all.push(name)
    else feed.versions[name] = [...versions].sort()
  }
  return { feed, updated }
}

function main(): void {
  const [npmZip, pypiZip] = process.argv.slice(2)
  if (!npmZip || !pypiZip) {
    console.error("usage: tsx scripts/build-osv-feed.ts <npm all.zip> <PyPI all.zip>")
    process.exit(2)
  }
  const npm = buildEcosystem(readMalRecords(npmZip), "npm")
  const pypi = buildEcosystem(readMalRecords(pypiZip), "PyPI")
  const size = (f: EcosystemFeed) => f.all.length + Object.keys(f.versions).length
  const counts = { npm: size(npm.feed), pypi: size(pypi.feed) }
  if (counts.npm < MIN_EXPECTED.npm || counts.pypi < MIN_EXPECTED.pypi) {
    console.error(`build-osv-feed: suspiciously small feed ${JSON.stringify(counts)} — not writing`)
    process.exit(1)
  }
  const feed = {
    schemaVersion: 1,
    source: "OSV MAL-* records (OpenSSF malicious-packages), https://osv.dev",
    updated: [npm.updated, pypi.updated].sort().at(-1),
    counts,
    npm: npm.feed,
    pypi: pypi.feed,
  }
  const body = JSON.stringify(feed) + "\n"
  writeFileSync(OUT, body)
  console.log(`osv-malicious.json: npm ${counts.npm}, pypi ${counts.pypi}, ${(body.length / 1024 / 1024).toFixed(2)} MB, updated ${feed.updated}`)
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main()
