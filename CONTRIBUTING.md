# Contributing to Forensicator

Thanks for considering a contribution. This project spans four collectors
(Windows/PowerShell, Linux/Bash, macOS/Bash, Network Devices/Python)
the guidance below applies across all of them
unless a platform's own README says otherwise.

## Before you start

* **Open an issue for anything non-trivial first**, especially a new
  detection rule, a new collected artifact, or a change to output format —
  it's a much shorter conversation before code is written than after.
* Check the platform's own README (`Windows/README.md`, `Linux/README.md`,
  `MacOS/README.md`, `Network/README.md`) for platform-specific
  conventions and known limitations before assuming something is a bug.
* Small, focused pull requests are much easier to review than large ones
  that touch several unrelated things.

## Repository layout

```
Windows/    PowerShell collector — Forensicator.ps1 (entrypoint) + Forensicator-Share/
Linux/      Bash collector — same Forensicator-Share/ pattern, POSIX-first
MacOS/      Bash collector — same pattern, Endpoint-Security-Framework limited
Network/    Python collector — SSH/Netmiko-based, talks to remote devices
```

Each collector keeps its detection knowledge base, rules, and shared
helpers under its own `Forensicator-Share/` (or `Forensicator-Share/`
equivalent) rather than a top-level shared library — the four collectors
are independent by design, not a shared framework, since they run on
fundamentally different systems (a live host vs. a remote SSH session).

## Adding a detection rule

The exact mechanism differs by platform — this is the most common kind of
contribution, so it's worth knowing where things live:

* **Windows/Linux/macOS (Sigma-based)**: most detections are Sigma rules
  under each collector's `Forensicator-Share/rules/<platform>/sigma/`,
  sourced from real SigmaHQ community rules. Bespoke, non-Sigma detections
  (things that need real logic, not just field matching) live in
  `Forensicator-Share/rules/<platform>/custom/*.json` — see any existing
  file there for the condition/item schema before writing a new one.
* **Network Devices (declarative + Python evaluator)**: rules are declared
  in `Network/Forensicator-Share/rules/rules.json` (which vendors it
  applies to, which artifact it reads, whether it needs a baseline) with
  the actual matching logic as a small named function in
  `Network/Forensicator-Share/rules/engine.py`. Every rule also needs a
  knowledge-base entry in `Network/Forensicator-Share/knowledge_base.py`
  (title, MITRE mapping, recommendations) or it'll render with a generic
  fallback. See `engine.py`'s module docstring for the three rule
  families (presence-type, pure-diff, allowlist/blocklist-membership) and
  which one your rule actually is — it changes how it behaves against an
  unpopulated baseline.
* **Operator-supplied IOCs** (no code change needed): `custom_iocs.txt` /
  `custom_hashes.txt` (Windows) and `custom_malicious_ips.txt` (Network)
  are meant to be appended to directly and are never overwritten by the
  auto-refresh logic.

Whichever platform, a new rule needs a real MITRE ATT&CK technique/tactic
mapping — check the current published ATT&CK matrix rather than guessing;
this project has had to correct mis-mapped techniques before (wrong tactic
for a technique ID) and it's an easy mistake to make from memory.

## Testing

* **Windows/Linux/macOS**: test against a real or VM instance of the
  target OS where possible. There's no unit-test harness for these — the
  standard verification is running the collector end-to-end and checking
  the HTML report and JSON findings.
* **Network Devices**: you don't need real hardware for most changes — a
  fixture-driven test (hand-built `CollectionResult`/`CommandResult`
  objects standing in for real device output, fed into
  `rules/engine.py`'s evaluators directly) covers rule logic without a
  live SSH session. Reserve real/lab-device testing (GNS3, EVE-NG, or a
  spare box) for changes to the connection layer (`collectors/base.py`) or
  a new vendor command. `python3 -m py_compile` on every changed file and
  validating any touched `.json` file are the minimum bar before opening a
  PR.
* Don't claim a fix works against a real device/OS/browser version you
  couldn't actually verify — say what you tested and what you couldn't,
  the same way you'd want a security tool's own changelog to be honest
  with you.

## Coding conventions

* Match the existing style in the file you're editing over introducing a
  new one — this codebase intentionally favors plain, explicit code over
  abstraction for abstraction's sake.
* No new external dependency without a real reason — check
  `requirements.txt`/the platform's dependency list first; several
  design decisions in this project (e.g., JSON over YAML, no templating
  engine for HTML reports) were made specifically to avoid adding one.
* Credentials and secrets: never write an actual password/API key/secret
  to `config.json` or any output file — only an *environment-variable
  name* is ever stored, resolved at runtime. See `SECURITY.md` for why
  this matters.
* Comments should explain *why*, not *what* — a non-obvious constraint, a
  workaround for a specific real bug, or a decision that would otherwise
  look wrong at a glance. If the code is self-explanatory, skip the
  comment.

## Pull requests

* Reference the issue you opened (or explain the "why" directly in the PR
  description if it's small enough to skip that step).
* Describe what you tested and how, per the Testing section above.
* Focus on accuracy, clarity, and usability — matching the spirit of the
  investigations this tool is meant to support.

## Code of Conduct

Participation in this project is governed by our
[Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting security issues

Please don't open a public issue for a security vulnerability — see
[SECURITY.md](SECURITY.md) for the private reporting process.
