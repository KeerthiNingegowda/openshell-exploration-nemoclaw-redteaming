# Day 1 — Linux processes, users & isolation primitives

**Why this is Day 1:** everything OpenShell does reduces to one sentence — *run an
untrusted process with less power than the thing that launched it*. Before any of
the sandbox machinery (`SANDBOX_UID`, `env_clear()`, seccomp, the network proxy)
makes sense, you need the ground floor: how a process comes to exist, what
identity it carries, and what the kernel will and won't let it touch. This is a
refresher, so it moves fast and points you at the primitives rather than
explaining what a shell is.

By the end you should be able to look at the `sandbox_env.py` constants and see
them not as strings but as *knobs on well-understood kernel mechanisms*.

> Platform note: the labs assume real Linux (`/proc`, `setuid`, `sudo -u`). On
> macOS several of these behave differently or don't exist — run them on the lab
> Unix box, a Linux VM, or a container (`docker run --rm -it debian bash`).

---

## 1. Concept: the process model

### fork/exec — how every process is born
There is essentially **one** way to make a new process on Unix and **one** way to
change what it's running:

- **`fork()`** — the calling process is cloned. The child is a near-identical copy
  of the parent: same code, same open file descriptors, a *copy* of the memory,
  and — critically for us — **a copy of the environment and the credentials
  (UID/GID)**. `fork()` returns twice: `0` in the child, the child's PID in the
  parent.
- **`exec()`** (the `execve` family) — replaces the current process image with a
  new program. Same PID, same open FDs (unless marked close-on-exec), **same
  environment unless you replace it**. This is the hinge: `exec` is where you get
  to decide what environment and identity the new program starts with.

The shell running `ls` does exactly this: `fork()`, then in the child optionally
adjust FDs / identity / environment, then `execve("/bin/ls", ...)`.

**Why it matters for OpenShell:** a sandbox supervisor launches workload children.
Between the `fork` and the `exec` is the *entire* window in which it can drop
privileges (`setuid`), scrub the environment (`env_clear()`), install seccomp
filters, and rewire file descriptors. Miss that window and the child inherits the
parent's power. The whole design lives in that gap.

### PID, parent/child, and the tree
Every process has a **PID** and a **PPID** (parent PID). Processes form a tree
rooted at PID 1 (`init`/`systemd`, or the container's entrypoint). When a parent
dies, orphans are re-parented (to PID 1, or a subreaper). This tree is what
`pstree` draws, and it's how you reason about "who launched this untrusted thing
and what did it inherit."

### Environment inheritance
The environment is just an array of `KEY=value` strings handed to `execve`. It is
**inherited by default** — the child gets a copy of the parent's. That default is
convenient and *dangerous*: if the parent holds `AWS_SECRET_ACCESS_KEY` in its
env, every child sees it too, unless someone deliberately clears it. Hold onto
this; it's the entire point of Lab 4 and the `USER_ENVIRONMENT` note.

### Users, UIDs, GIDs
Identity is numeric. A process carries a **UID** and **GID** (plus supplementary
groups, and the real/effective/saved triples). Names like `nobody` are just
`/etc/passwd` lookups over the number — the kernel only ever checks numbers. This
is why OpenShell can run with a raw `SANDBOX_UID` and *no* `/etc/passwd` entry:
the number is all `setuid()` and the permission checks need.

- **real UID** — who you are.
- **effective UID (euid)** — who the kernel uses for permission checks *right now*.
- **saved UID** — a stash so a privileged process can drop and later restore.

### setuid — two meanings, don't conflate them
1. **The `setuid()` syscall** — a running (privileged) process *changing* its UID,
   typically to drop from root to an unprivileged user. This is what a supervisor
   does after `fork` to hand the child less power. Dropping is one-way if you also
   clear the saved UID — that's the safe pattern.
2. **The setuid *bit*** (`chmod u+s`, the `s` in `-rwsr-xr-x`) — a file permission
   that makes a program run with the **file owner's** UID instead of the caller's.
   `sudo` and `passwd` are setuid-root. This is a privilege *escalation* mechanism
   and a classic attack surface — the inverse of what a sandbox wants.

### File permissions & `/proc`
- **Permissions** are the classic `rwx` for user/group/other, checked against the
  process's effective UID/GID. This is the coarse-grained "what can this UID
  touch" layer you'll feel directly in Lab 2.
- **`/proc`** is a virtual filesystem — a live window into the kernel's process
  table. `/proc/<pid>/environ`, `/proc/<pid>/status`, `/proc/<pid>/maps`, etc. are
  synthesized on read. It's how you *observe* everything above from the outside,
  and (spoiler) it's also an information-leak surface a sandbox has to think about.

---

## 2. Lab: read the process tree and a process's guts

**Goal:** get fluent at inspecting a live process's identity and environment from
the outside via `/proc`.

```bash
# The tree — see parent/child relationships and PIDs
ps -ef                      # every process, with PPID column
pstree -p                   # the tree, with PIDs; find your shell in it
echo $$                     # PID of your current shell

# Start a long-lived victim we can poke at
sleep 3600 &
SLEEP_PID=$!
echo "victim pid = $SLEEP_PID"

# Its identity and state
cat /proc/$SLEEP_PID/status | grep -E '^(Name|Pid|PPid|Uid|Gid|State)'
#   Uid:  <real> <effective> <saved> <fs>   <-- the triples, live
#   Gid:  ...

# Its environment (NUL-separated — translate to newlines)
cat /proc/$SLEEP_PID/environ | tr '\0' '\n'

# What files/sockets does it hold open?
ls -l /proc/$SLEEP_PID/fd

kill $SLEEP_PID
```

**Observe:**
- The `Uid:` line in `status` shows all four UID variants at once. For a normal
  process they're identical; after a privilege drop they diverge.
- `environ` is a snapshot from *process start*. That's why it's such a clean audit
  target — it shows exactly what was handed to `execve`.

**Questions to answer yourself:**
- Whose child is your `sleep`? Trace `PPid` up with `pstree -p` until you hit PID 1.
- Can you read `/proc/1/environ`? Why not (as a normal user)? *(Permission is keyed
  on the owning UID — you can only read the environ of processes you own.)* This
  is your first taste of `/proc` as a controlled leak surface.

---

## 3. Lab: run a process as another UID and watch it fail

**Goal:** *feel* the permission boundary — the thing a sandbox leans on to contain
a workload.

```bash
# Who am I right now?
id

# Run a command as the unprivileged 'nobody' user
sudo -u nobody id
#   uid=65534(nobody) gid=65534(nogroup) ...   <-- different numeric identity

# Create a private file, then try to touch it as nobody
echo "secret" > /tmp/mine.txt
chmod 600 /tmp/mine.txt
cat /tmp/mine.txt                       # you: works
sudo -u nobody cat /tmp/mine.txt        # nobody: Permission denied

# nobody also can't write where you can
sudo -u nobody touch /root/should_fail  # Permission denied
sudo -u nobody sh -c 'echo hi > /tmp/mine.txt'   # denied — 600, wrong owner

# Compare the /proc view of a nobody process
sudo -u nobody sleep 300 &
NPID=$!
grep -E '^(Uid|Gid)' /proc/$NPID/status   # different numbers than 'id' showed
kill $NPID
```

**Observe:** nothing about `nobody` is special except its *number*. The kernel
denied the reads/writes purely by comparing UID 65534 against file ownership and
mode bits. That is the entire containment primitive at this layer — and it's why
"run the workload as a low, unprivileged UID" is step one of any sandbox.

**Connect it forward:** when OpenShell resolves a `SANDBOX_UID`, this is the exact
mechanism it's arming. The supervisor `setuid()`s the child to that number so
every subsequent file/permission check the workload triggers is evaluated as the
unprivileged identity you just role-played.

---

## 4. Lab: `env` vs `env -i` — feel what `env_clear()` means

**Goal:** internalize the single most security-relevant default in the whole
model: *the environment is inherited unless you deliberately wipe it.*

```bash
# Put a "secret" in your environment, as if you were a privileged parent
export FAKE_SECRET="pretend-this-is-an-API-key"

# Default: children INHERIT the environment
env | grep FAKE_SECRET          # present
bash -c 'echo child sees: $FAKE_SECRET'   # child sees it too — inherited

# env -i: start the child with an EMPTY environment (this IS env_clear())
env -i bash -c 'echo child sees: [$FAKE_SECRET]'   # empty — scrubbed
env -i env                      # near-nothing; you build the env back up explicitly

# The controlled pattern: clear, then inject ONLY what's allowed
env -i PATH=/usr/bin:/bin HOME=/tmp bash -c 'env'
#   child gets exactly PATH and HOME — nothing leaked from the parent
```

**Observe the two worlds:**
- **`env <cmd>`** — inherit everything. Convenient, leaky. `FAKE_SECRET` rides
  along into every child whether it should or not.
- **`env -i <cmd>`** — start from *nothing* and hand-pick what goes in. This is the
  userspace mirror of Rust's `Command::env_clear()`: wipe the inherited
  environment, then set only the vetted variables.

**This is the whole idea behind `USER_ENVIRONMENT`.** The supervisor does *not*
let the workload inherit the supervisor's environment (which may hold gateway
tokens, TLS paths, and other bootstrap identity). Instead it `env_clear()`s the
child and injects only the user-declared variables that were serialized into
`OPENSHELL_USER_ENVIRONMENT`. You just did that by hand with `env -i PATH=... `.

---

## 5. Unlocks — reading `sandbox_env.py` with new eyes

Open `openshell_core/sandbox_env.py`. With Labs 1–4 behind you, these constants
stop being opaque strings:

### `SANDBOX_UID` / `SANDBOX_GID` (lines 108–118)
> *"Resolved sandbox UID used to override run_as_user … Supervisor reads this at
> startup and uses it directly with `setuid()`/`chown()` **without requiring an
> `/etc/passwd` entry** in the sandbox image."*

This is **Lab 3**, automated. The supervisor takes a raw number and `setuid()`s
the workload to it — exactly the `sudo -u nobody` boundary you exercised, except
the identity is a policy-resolved number, not a named account. The "no
`/etc/passwd` needed" line is the payoff of the *"identity is numeric"* concept in
§1: the kernel only ever needed the number, so the image doesn't need a passwd
entry to name it.

### `env_clear()` for SSH children — the `USER_ENVIRONMENT` note (lines 91–95)
> *"Supervisor deserializes this at startup and injects the variables into SSH
> child processes (which use `env_clear()` for security isolation)."*

This is **Lab 4**, verbatim, in production. The bootstrap identity the supervisor
holds — gateway JWT (`SANDBOX_TOKEN` / `SANDBOX_TOKEN_FILE`), mTLS material
(`TLS_CA/CERT/KEY`), endpoint config — must **not** be inherited by the untrusted
workload. So the child is `env_clear()`'d (your `env -i`) and then *only* the
user-declared variables from `OPENSHELL_USER_ENVIRONMENT` are injected (your
`env -i KEY=value ...`). The fork/exec window from §1 is where this happens.

### "Bootstrap identity not inherited by child processes"
Now you can state the invariant precisely and back it with mechanism: **the
supervisor's environment carries privilege (tokens, cert paths); the fork→exec
transition is the one place to strip it; `env_clear()` is the strip; the numeric
`SANDBOX_UID` drop ensures that even if something leaked, the child's kernel-level
identity has no power to use it.** Two independent layers — environment scrubbing
and UID reduction — both armed in the same fork/exec gap.

---

## Checklist

- [ ] I can explain fork/exec and name what the child inherits (FDs, env, UID/GID).
- [ ] I can read a live process's UID triples and environment from `/proc`.
- [ ] I ran a process as another UID and watched the kernel deny it access.
- [ ] I can articulate the difference between `env` and `env -i` — and why the
      latter is `env_clear()`.
- [ ] I can point at `SANDBOX_UID` and `USER_ENVIRONMENT` in `sandbox_env.py` and
      explain the kernel mechanism each one drives.

## Going deeper (optional)
- `man 2 execve`, `man 2 setuid`, `man 2 fork`, `man 5 proc`
- `strace -f -e trace=execve,setuid,setgid bash -c 'sudo -u nobody id'` — watch the
  syscalls fire in order.
- `capabilities(7)` — the finer-grained successor to the all-or-nothing root
  model; a natural Day 2 thread toward seccomp and namespaces.
