---
name: New Detection Rule
about: Propose a new malware/scam detection rule
title: "[RULE] "
labels: new-rule
---

## Rule Type

- [ ] YARA-style pattern (regex matching in code)
- [ ] Malicious npm package
- [ ] Malicious PyPI package
- [ ] Known bad hash
- [ ] User profile risk factor

## Proposed Rule

**ID:** (e.g. `DISCORD_WEBHOOK_EXFIL`)
**Severity:** critical / high / medium / low
**Pattern/Name:**

```
(paste the regex pattern, package name, or hash here)
```

**Description:**

(What does this detect? Why is it malicious?)

## Evidence

(Link to malware report, CVE, blog post, or sample. Do NOT paste actual malware code here.)

- [ ] Verified against at least one real malicious sample
- [ ] Pattern does not trigger on popular legitimate packages/code
- [ ] Source is public and credible (VirusTotal, security blog, CVE, etc.)

## False Positive Assessment

(Are there legitimate programs that would trigger this rule? How common?)
