# Contributing to Flagrix Detection Rules

Thank you for helping keep developers safe!

## What belongs here

- **YARA-style regex rules** for detecting malicious code patterns
- **Malicious npm/PyPI packages** that are confirmed malware (not just unmaintained)
- **Known bad file hashes** sourced from public threat intel
- **User profile risk factors** for GitHub account analysis

## What does NOT belong here

- Packages that are merely abandoned/deprecated (not malicious)
- Suspicion-only reports without evidence
- Proprietary or classified threat intelligence
- Actual malware samples or shellcode

## How to add a rule

### 1. Choose the right file

| What you're adding | File |
|--------------------|------|
| Code pattern (regex) | `rules/github/repository.yaml` |
| Obfuscation pattern | `rules/github/obfuscation.yaml` |
| User profile risk factor | `rules/github/user-profile.yaml` |
| Malicious npm package | `packages/malicious-npm.yaml` |
| Malicious PyPI package | `packages/malicious-pypi.yaml` |
| Bad file hash | `hashes/known-bad.yaml` |

### 2. Rule format (YARA-style)

```yaml
- id: RULE_ID_IN_CAPS
  name: Human-Readable Name
  description: >
    What does this detect and why is it dangerous?
    Link to source: https://example.com/threat-report
  severity: critical  # critical | high | medium | low
  confidence: high    # optional: high | medium | low
  context: keyboard-capture # optional scanner-core behavioral check
  pattern:
    type: regex
    value: "your.*regex.*pattern"
    file_extensions: [".js", ".ts", ".py"]
  tags: [category, sub-category]
```

**Severity guide:**
- `critical` — Definitive malware indicator (reverse shell, confirmed APT pattern)
- `high` — Strong indicator with low false-positive rate
- `medium` — Suspicious but may have legitimate uses
- `low` — Weak signal, informational only

Severity is potential impact; `confidence` is certainty that the match really
has that behavior. Regex-only heuristics should use `medium` or `low`
confidence. Use a supported `context` check when a dangerous behavior requires
multiple correlated actions—for example, a keyboard listener is only
keylogging when it also reads and stores or transmits pressed keys.

### 3. Package format

```yaml
- name: malicious-package-name
  severity: critical
  source: lazarus  # or: npm-audit, pypi-audit, virustotal, cve-YYYY-NNNNN
  description: What it does and how it was confirmed malicious
  added: "YYYY-MM-DD"
  typosquat_of: legitimate-package  # optional
  references:
    - https://link-to-threat-report
```

### 4. Test your rule

```bash
npm install
npm run build
npm run validate
```

Both commands must pass without errors.

### 5. Submit your PR

Use the PR template. Make sure you have:
- Evidence linking to a public source (VirusTotal, CVE, security blog)
- Tested the pattern doesn't false-positive on popular legitimate code

## Rule ID conventions

- Use `SCREAMING_SNAKE_CASE`
- Group by threat category: `LAZARUS_`, `BEAVERTAIL_`, `BACKDOOR_`, `CRYPTO_`, `EXFIL_`, etc.
- Be specific: `DISCORD_WEBHOOK_EXFIL` is better than `SUSPICIOUS_NETWORK`

## Questions?

Open an issue or start a discussion. We respond within 48 hours.
