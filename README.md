# Flagrix Detection Rules

Community-maintained threat detection rules for [Flagrix](https://flagrix.io) — the security scanner for developers.

Identify malicious code, supply chain attacks, scam patterns, and suspicious GitHub profiles before you clone or collaborate.

## What's in here

| Path | Contents |
|------|----------|
| `rules/github/repository.yaml` | YARA-style patterns: malware signatures, hardcoded secrets, backdoors, network exfiltration, social engineering |
| `rules/github/obfuscation.yaml` | Obfuscation technique detection (base64, hex, long lines, eval abuse) |
| `rules/github/user-profile.yaml` | Risk scoring weights + thresholds for GitHub account analysis (compiled into `userProfileRules`, consumed live by the scanner) |
| `packages/malicious-npm.yaml` | Confirmed malicious npm packages (Lazarus Group, typosquats) |
| `packages/malicious-pypi.yaml` | Confirmed malicious PyPI packages |
| `hashes/known-bad.yaml` | SHA-256 hashes of known malicious files |

> **On file hashes:** Flagrix scanning is pattern-based (regex/YARA over source and
> dependencies), not hash-based. `knownBadHashes` carries a few sourced IOCs
> (Shai-Hulud / CHAINDROP payloads) for consumers that want them, but
> scanner-core doesn't match on hashes.

## Detection categories

Together with the heuristics built into [scanner-core](https://github.com/flagrix-io/flagrix-scanner-core), Flagrix covers **22 detection categories**:

1. **Malware signatures** — Lazarus BeaverTail / InvisibleFerret / PolinRider patterns
2. **Obfuscated code** — Base64, hex strings, eval and `new Function` abuse, `fromCharCode` and charcode arrays, long-line attacks
3. **Hardcoded secrets** — AWS, GitHub, Stripe, npm and AI-provider keys, private-key blocks, wallet keys, DB connection strings
4. **Suspicious network** — Discord webhooks, Telegram tokens, Pastebin URLs, ngrok tunnels, URL shorteners, suspicious TLDs
5. **Data exfiltration** — Clipboard access, cookie theft, keyloggers, environment variables sent to webhooks
6. **Backdoors** — Reverse shells, RCE endpoints, dynamic require, hardcoded auth bypass
7. **Supply chain attacks** — Install scripts that download or run code, preinstall droppers
8. **Suspicious file access** — SSH/AWS credential reads, system files, browser password databases, macOS Keychain dumps
9. **Crypto mining** — stratum+tcp, XMRig, cryptonight patterns
10. **Code integrity** — Minified code in source repos, missing license/README, placeholder secrets, a Flask debugger exposed on all interfaces
11. **Social engineering** — README urgency tactics, security bypass instructions, requests for wallet secrets
12. **Non-English comments** — Share of comment text in other languages, shown for context only (it doesn't raise the verdict on its own)
13. **User profile risk** — Account age, follower patterns, activity analysis
14. **Editor & agent auto-execution** — VS Code `folderOpen` tasks, Claude Code hooks, MCP configs, hidden agent instructions *(needs scanner-core ≥ 0.4, which scans these files)*
15. **Loader tradecraft** — HTTP-response eval, `global['!']` markers, whitespace-padded config injection, GlassWorm invisible Unicode, blockchain dead drops
16. **Worm & campaign IOCs** — Shai-Hulud / CHAINDROP droppers and artifacts, known 2026 C2 / payload hosts, request catchers
17. **Paste-and-run lures** — encoded or hidden-window shell one-liners in READMEs and task files
18. **Malicious dependencies** — npm and PyPI packages from the curated list and the OSV feed below, matched version-aware against `package.json`, `requirements.txt`, `setup.py` and `Pipfile`
19. **Typosquats** — dependency names one or two edits away from popular npm packages (checked against npm download counts to cut false alarms)
20. **Git-history signals** — backdated pushes and recent force pushes
21. **Disguised files** — JavaScript posing as font files, suspicious hidden files
22. **CI workflow abuse** — GitHub Actions steps that dump repository secrets

## How Flagrix uses these rules

The Flagrix extension fetches `signatures.json` from this repository every 6 hours. When you scan a GitHub repository or user profile, the extension matches your target against these rules locally in your browser. Nothing is sent to a Flagrix server.

The `signatures.json` is compiled from the rule, package, and hash YAML files by running:

```bash
npm install
npm run build
```

### OSV malicious-package feed

`osv-malicious.json` lists every npm and PyPI package that the [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) project has confirmed malicious (OSV `MAL-*` records): about 222k npm and 12k PyPI names, 5.6 MB (1.4 MB gzipped). It's far too large to embed in `signatures.json`, so it is a separate file. Scanners fetch it and match dependencies locally, so names never leave the device. `packages/malicious-npm.yaml` stays the curated list with descriptions and sources.

Format: per ecosystem, `all` lists packages malicious in every version, and `versions` maps the rest to affected versions or ranges such as `>=1.0.0 <1.2.11`. PyPI names are PEP 503-normalised.

The [OSV feed workflow](.github/workflows/osv-feed.yml) rebuilds it nightly from the official OSV dumps and commits only when the data changed. To build it by hand:

```bash
curl -sSfLo /tmp/npm.zip https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip
curl -sSfLo /tmp/pypi.zip https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip
npm run build:osv -- /tmp/npm.zip /tmp/pypi.zip
```

## Contributing

Found a new malware package? Spotted a pattern not covered? See [CONTRIBUTING.md](CONTRIBUTING.md).

Contributions need:
1. Evidence linking to a public source (VirusTotal, CVE, security blog post)
2. Tested against a real sample
3. `npm run build && npm run validate` passes

## AI Disclosure

This project leverages Claude AI for boilerplate generation, test-suite expansion, and optimization. All AI-generated code is strictly reviewed, refactored, and verified by human maintainers before merging.

## License

MIT — use freely in your own security tools. Attribution appreciated.

---

*Part of the [Flagrix](https://flagrix.io) open-core security platform.*
