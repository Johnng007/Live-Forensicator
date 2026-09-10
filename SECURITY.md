# Security Policy

Forensicator is used during live incident response, often on systems that
are themselves under investigation or actively compromised. We take
vulnerabilities in the toolkit itself seriously — a bug in the collector is
a bug in the evidence chain.

## Supported Versions

Security fixes are provided for the latest released version of each
platform collector (Windows, Linux, macOS, Network Devices) and for
Forensicator Enterprise. Older releases are not patched — please upgrade
before reporting an issue that may already be fixed.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**
Public disclosure before a fix is available puts every current user of the
toolkit at risk, particularly given it's frequently run with elevated
privileges during real incident response.

Instead, report privately:

* Email **hello@raptormatics.com**
  
* Or use GitHub's [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) feature on this repository, if enabled

Please include:

* Which collector/component is affected (Windows/Linux/macOS/Network/Enterprise) and version
* Steps to reproduce, or a proof-of-concept
* The potential impact as you see it (e.g., arbitrary code execution, credential exposure, evidence tampering)

We aim to acknowledge reports within **5 business days** and to provide a
remediation timeline once the issue is confirmed. We'll credit reporters in
the fix's release notes unless you ask us not to.

## Scope

**In scope** — vulnerabilities in Forensicator's own code, for example:

* Arbitrary code/command execution triggered by attacker-controlled input
  (e.g., a crafted filename, registry value, or device banner that a
  collector reads and mishandles)
* Credential or secret exposure — e.g., a password, API key, or encryption
  key ending up in a log file, JSON finding, or HTML report where it
  shouldn't. Every collector's documented convention is that only an
  *environment-variable name* (`password_env`, `secret_env`, `api_key`) is
  ever stored in `config.json` or written to output — a bug that leaks the
  actual secret value anywhere is a real finding.
  See [collector/live-forensicator/Network/README.md](Network/README.md#-notes) for one example of this convention.
* Path traversal or injection in artifact/report writing that could let
  collected data escape the intended output directory
- Weaknesses in the optional AES-256 artifact-encryption implementation
  (Windows/Linux/macOS/Network Devices)
* A dependency pinned by this project with a known, exploitable
  vulnerability

**Out of scope** — these are not Forensicator vulnerabilities:

* Forensicator correctly reporting malware, misconfiguration, or compromise
  that already exists on the system it's run against — that's the tool
  doing its job
* Findings that require an attacker to already have the level of access
  needed to run the collector itself (e.g., local admin/root) — live
  forensics tooling inherently requires privileged execution
* Issues in third-party tools this project bundles or shells out to (e.g.,
  Netmiko, Sigma rule content, winpmem/osxpmem) — please report those
  upstream, though we're happy to hear about them too if they affect how
  we use the dependency

## Design Notes for Reviewers

A few things worth knowing if you're auditing this codebase:

* Every collector treats device/host credentials the same way: read from an
  environment variable named in `config.json`, never written to disk in
  plaintext by the tool itself.
* The Network Devices collector is read-only by design — no collected
  command is ever a configuration-mutating one, and it never enters
  configuration mode on any device.
* Threat-intel feed URLs (`config.json`'s `hash_source`/`url_source` on
  Windows, `threat_intel.malicious_ip_sources` on Network Devices) are
  fetched over HTTPS with a bounded timeout and merged into local cache
  files — a compromised feed source could inject bad IOC data, but not
  arbitrary code, since fetched content is only ever compared as text, never
  executed or deserialized.
