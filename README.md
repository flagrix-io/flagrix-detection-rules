# Flagrix Detection Rules

Community-maintained threat detection rules for [Flagrix](https://flagrix.io) — the security scanner for developers.

Identify malicious code, supply chain attacks, scam patterns, and suspicious GitHub profiles before you clone or collaborate.

## What's in here

| Path | Contents |
|------|----------|
| `rules/github/repository.yaml` | YARA-style patterns: malware signatures, hardcoded secrets, backdoors, network exfiltration, social engineering |
| `rules/github/user-profile.yaml` | Risk scoring weights for GitHub account analysis |
| `rules/github/obfuscation.yaml` | Obfuscation technique detection (base64, hex, long lines, eval abuse) |
| `rules/pdf/malicious.yaml` | PDF threat patterns (embedded JS, auto-actions, executable links) |
| `rules/pdf/job-scam.yaml` | Social engineering text patterns in recruitment PDFs |
| `packages/malicious-npm.yaml` | Confirmed malicious npm packages (Lazarus Group, typosquats) |
| `packages/malicious-pypi.yaml` | Confirmed malicious PyPI packages |
| `hashes/known-bad.yaml` | SHA-256 hashes of known malicious files |

> **On file hashes:** Flagrix scanning is pattern-based (regex/YARA over source and
> dependencies), not hash-based, so `knownBadHashes` is intentionally empty by
> default. The field exists in the schema for consumers that want to add hash IOCs.

## Detection categories

The repository covers **13+ detection categories**:

1. **Malware signatures** — Lazarus/BeaverTail/InvisibleFerret APT patterns
2. **Obfuscated code** — Base64, hex strings, eval abuse, long-line attacks
3. **Hardcoded secrets** — AWS keys, GitHub tokens, Stripe keys, API keys
4. **Suspicious network** — Discord webhooks, Telegram tokens, Pastebin URLs, ngrok tunnels
5. **Data exfiltration** — Clipboard access, cookie theft, keyloggers, form data theft
6. **Backdoors** — RCE endpoints, dynamic require, hardcoded auth bypass
7. **Supply chain attacks** — Malicious postinstall scripts, executable downloads
8. **Suspicious file access** — SSH/AWS credential reads, browser password DB access
9. **Crypto mining** — CoinHive, stratum+tcp, XMRig, cryptonight patterns
10. **Code integrity** — Minified code in source repos, missing license/README
11. **Social engineering** — README urgency tactics, security bypass instructions
12. **Non-English comments** — Detects non-English code comments (Lazarus indicator)
13. **User profile risk** — Account age, follower patterns, activity analysis

## How Flagrix uses these rules

The Flagrix extension fetches `signatures.json` from this repository every 6 hours. When you scan a GitHub repository or user profile, the extension matches your target against these rules locally in your browser — no data leaves your machine.

The `signatures.json` is compiled from all YAML files by running:

```bash
npm install
npm run build
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
