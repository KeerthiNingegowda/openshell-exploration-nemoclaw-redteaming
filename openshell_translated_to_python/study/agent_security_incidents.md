# Agent security incidents — hook ledger

A running, lightweight collection of **real-world security incidents involving AI
agents**, kept as source material for the OpenShell blog series (esp. Part 1's
hook and Part 4's red-team framing).

## Discipline for this file (from the "keep facts airtight" rule)

Every entry must carry:
- **Root-cause class** — *what kind* of failure it was. This decides which post it
  can honestly hook. An isolation/privilege failure can back a primitives demo; a
  web-app misconfig can only set mood.
- **Which part it serves** — hook (mood-setting) vs. demo (illustrates a specific
  primitive) vs. red-team framing.
- **Verification status** — `confirmed (source linked)` / `unverified` /
  `disputed`. A blog hook lives on accuracy; nothing graduates to a published post
  until it's `confirmed` with a primary source.

**Mapping guide — does an incident back a Part 1 *primitive demo*?**
Only if the failure was *an agent process having more power / more environment /
more reach than it should*. Those map to `env_clear()`, `SANDBOX_UID`, network
policy. Everything else (database misconfig, prompt-injection-of-content, leaked
dashboard) is a **hook**, not a **demo** — great for stakes, wrong for showing a
primitive.

---

## Entries

### Moltbook — exposed Supabase key + missing RLS
- **Date:** discovered **Jan 31, 2026, 21:48 UTC**; fully patched **Feb 1, 2026,
  01:00 UTC** (~3-hour disclosure-to-fix window).
- **Discovered by:** Wiz Research (Gal Nagli); security researcher Jameson
  O'Reilly independently found the same misconfiguration.
- **What happened:** Moltbook — a viral social network built exclusively for
  autonomous AI agents (1.5M registered agents vs. only ~17K human owners, an 88:1
  bot-to-human ratio) — had a hardcoded public Supabase API key in client-side
  JavaScript. Combined with missing Row-Level Security (RLS) on the backend, this
  gave anyone viewing page source unauthenticated read-and-write access to the
  entire production database.
- **Data exposed:** ~4.75M total records, including **1.5M API authentication
  tokens**, 35,000 owner emails (+29,631 from an observers table), and 4,060
  private direct messages between agents. Complete DB schema exposed.
- **Root-cause class:** web-app / data-layer misconfiguration (client-side secret
  exposure + missing authorization). **Not** a process-isolation failure.
- **Which part it serves:** **Part 1 hook only** — sets the "agents are being
  shipped recklessly, the stakes are real" mood. **Does NOT back a primitive
  demo** — no `/proc`, `env`, or `setuid` control would have prevented it; the
  failure was in the data layer, not the agent's runtime privilege.
- **Verification status:** ✅ `confirmed` — multiple independent sources incl. Wiz
  primary writeup (see below).
- **Sources:**
  - Wiz Research (primary): https://www.wiz.io/blog/exposed-moltbook-database-reveals-millions-of-api-keys
  - Techzine: https://www.techzine.eu/news/security/138458/moltbook-database-exposes-35000-emails-and-1-5-million-api-keys/
  - Wikipedia: https://en.wikipedia.org/wiki/Moltbook
- **Blog-worthy angle:** the "vibe coding" pull-quote is gold. Founder Matt
  Pritchard: *"I didn't write a single line of code for @moltbook. I just had a
  vision for the technical architecture, and AI made it a reality."* Gal Nagli
  (Wiz) called it *"a textbook warning against shipping unchecked AI-generated
  code."* Strong opener for "why does an agent stack need a security layer at
  all?" Then pivot: *"that was the data layer — but the scarier class is when the
  agent process itself has too much power. That's the rest of this post."* Clean
  handoff from hook → primitives.

---

## Wanted: incidents that back the *primitive demos*

Gaps to fill — looking for confirmed cases where the root cause was runtime
over-privilege (these are the ones that make the `/proc` demos land):
- [ ] **Secret exfil via inherited environment** — agent/child process read creds
      it should never have inherited. → backs `env_clear()` / `USER_ENVIRONMENT`.
- [ ] **Over-privileged agent identity** — agent ran as root / effective-root and
      reached something it shouldn't. → backs `SANDBOX_UID` / privilege drop.
- [ ] **Egress abuse** — agent exfiltrated data / called an unapproved endpoint
      with no network policy. → backs the L7 policy + network proxy (Part 2/6).
- [ ] **Prompt-injection → tool-use → real action** — the canonical agent failure
      chain; frames Part 4 red-team.
