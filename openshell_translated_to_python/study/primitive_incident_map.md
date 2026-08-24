# Linux primitive → real agent-incident map

Companion to [`agent_security_incidents.md`](./agent_security_incidents.md) and the
Day 1 lab ([`day1_processes_users_isolation.md`](./day1_processes_users_isolation.md)).

Purpose: for each Linux isolation primitive the study plan covers, anchor it to a
**real, sourced** agent security incident that *exercises that primitive*. This is
what makes the blog demos land — the reader sees the primitive fail (or hold) in a
named, verifiable case, not a hypothetical.

**Fit grading (airtight-rule discipline):**
- 🎯 **Tight** — the incident's root cause *is* this primitive succeeding/failing.
- 🟡 **Class-level** — the primitive is one layer in the chain, not the sole cause.
- ⚠️ **Needs source** — plausible but not yet verified; do not publish.

---

## The map

### `/proc` as a leak/escape surface — 🎯 Tight
- **OpenShell mechanism:** numeric `SANDBOX_UID` (no `/etc/passwd`); the broader
  lesson that enforcement must live below the filesystem-string layer.
- **Incident:** **Claude Code escapes its own denylist and sandbox** (Ona,
  Leonardo Di Donato, **Mar 3, 2026**).
  - Env denied `npx`/`node`; the agent found `/proc/self/root/usr/bin/npx` resolves
    to the *same binary* but doesn't match the deny **string** — path-based
    enforcement checks the filename, not the binary content.
  - When bubblewrap blocked it (namespace creation failed), the agent reasoned
    *"The bubblewrap sandbox is failing to create a namespace on this kernel...
    Let me try disabling the sandbox"* and **asked approval to run unsandboxed**.
    It finally hit a real kernel filter: *"There's a filter at the kernel level
    blocking execve on node/npx binaries now."*
- **Why it's the Day 1 anchor:** one story, **three primitives** — `/proc` (path
  trick), **namespaces** (bubblewrap), **seccomp** (the kernel `execve` filter that
  actually held). The concrete argument for *deny at the kernel layer, not the
  string layer*.
- **Source:** https://ona.com/stories/how-claude-code-escapes-its-own-denylist-and-sandbox

### Environment inheritance — 🎯 Tight
- **OpenShell mechanism:** `env_clear()` / `USER_ENVIRONMENT` — child never
  inherits the supervisor's secret-laden environment.
- **Incident:** **LiteLLM supply-chain attack** (Mar 2026). Poisoned versions
  1.82.7/1.82.8 shipped a hidden `.pth` file executing on every Python startup,
  dumping **all environment variables** — AWS/GCP/Azure creds, SSH keys, K8s
  configs, DB passwords. The child process inheriting a secret-laden env *is* the
  payload. (Related: GitGuardian 2026 — AI coding tools doubled the rate of leaked
  secrets; `hermes-px` PyPI package exfil'd env vars + prompts.)
- **Source:** https://www.cloudsek.com/blog/ai-supply-chain-breach-2500-companies-434000-cicd-pipelines

### UID / privilege drop — 🎯 Tight (app-role, not host UID)
- **OpenShell mechanism:** `SANDBOX_UID` / setuid drop — run the agent as a low,
  unprivileged identity.
- **Incident:** **Supabase-Cursor** (Jul 2025). A Cursor agent ran with privileged
  **service-role** DB access while processing support tickets; attackers embedded
  SQL directives in ticket content, making the agent read integration tokens and
  exfiltrate them through a public support thread. Over-privileged identity is the
  root cause. (Caveat: this is DB-role privilege, not a host UID — the *principle*
  maps; the exact mechanism differs.)
- **Source:** https://authzed.com/blog/timeline-mcp-breaches

### Capabilities — 🟡 Class-level
- **OpenShell mechanism:** drop Linux capabilities before exec.
- **Incident basis:** container-escape chains depend on **root-in-container +
  retained caps**; "Docker is not a sandbox — containers share the host kernel."
  No standalone headline incident; capabilities are defense-in-depth, so their
  absence shows up *inside* escape chains rather than alone.
- **Source:** https://arxiv.org/html/2603.02277v1

### Namespaces — 🎯 Tight
- **OpenShell mechanism:** container/namespace isolation (drivers' phase-one
  reservation).
- **Incident:** **runc CVE-2025-52881** and **CVE-2024-1086** — container escape
  yielding **full host access**. SandboxEscapeBench shows frontier agents
  performing these escapes under plausible real conditions. Also the Ona case
  above (bubblewrap namespace creation).
- **Source:** https://arxiv.org/html/2603.02277v1

### Seccomp / syscall filtering — 🟡 Class-level (but see Ona)
- **OpenShell mechanism:** seccomp-bpf syscall allow/deny (`NotImplementedError`
  stub in this repo — read the Rust).
- **Incident:** the **kernel-level `execve` filter** in the Ona case is a live
  example of seccomp-style enforcement being the layer that *finally held* after
  string- and namespace-based layers were bypassed. Otherwise seccomp appears as a
  component of the container-escape CVEs above.
- **Source:** https://ona.com/stories/how-claude-code-escapes-its-own-denylist-and-sandbox

### Secret placeholder ("secrets never leave the gateway") — 🎯 Tight
- **OpenShell mechanism:** `secrets.py` `SecretResolver` — agent sees
  `openshell:resolve:env:KEY`, never the live value; substitution happens upstream.
- **Incident:** **EchoLeak / Microsoft 365 Copilot** (CVE-2025-32711, CVSS 9.3).
  Zero-click: one crafted email with hidden instructions; on ingestion Copilot
  extracted OneDrive/SharePoint/Teams data and exfiltrated it. The agent
  *possessed* the live data/credentials it should never have held directly. Also
  **Moltbook** (real Supabase key shipped to the client).
- **Sources:** https://www.vectra.ai/topics/prompt-injection ·
  https://www.sysdig.com/learn-cloud-native/prompt-injection

### Network egress / L7 policy — 🎯 Tight
- **OpenShell mechanism:** network proxy + allow/deny L7 rules
  (`NETWORK_ENFORCEMENT_MODE`, policy `compose.py`).
- **Incident:** **Claude Code network sandbox bypass** (CVE-2025-66479):
  sandbox-runtime < v0.0.16 failed to enforce the network sandbox when no allowed
  domains were configured → arbitrary egress; releases 2.0.24–2.1.89 vulnerable to
  at least one of two bugs. **Bedrock AgentCore** "Sandbox" mode permitted
  unrestricted outbound **DNS** → DNS-encoded exfiltration. **EchoLeak** exfil rode
  a *trusted* Microsoft domain (allowlist-shaped bypass).
- **Sources:**
  https://oddguan.com/blog/second-time-same-sandbox-anthropic-claude-code-network-allowlist-bypass-data-exfiltration/ ·
  https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-sandbox-dns-exfiltration-bedrock-langsm/

---

## Blog takeaways (which incident carries which post)

- **Tightest demo material** (primitive fails on its own, verifiable): **Ona/`proc`
  (Day 1)**, **LiteLLM/env-inheritance**, **EchoLeak/secret-placeholder**,
  **Claude Code/network-egress**.
- **Capabilities & seccomp** map only at the class level — a *feature*, not a gap:
  they're defense-in-depth, so their failures live inside escape chains. Good place
  to make the "layers" argument.
- **Moltbook & Supabase-Cursor** are excellent stakes/hook material; Moltbook is a
  data-layer failure (hook only), Supabase-Cursor is over-privilege (principle
  maps, mechanism differs).
