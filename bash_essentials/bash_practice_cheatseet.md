# Bash Cheatsheet

A dumbed-down reference for special variables, forking behaviour, and file paths in bash.

## Special variables

```bash
$$    # PID of the current process (a ( ... ) subshell gets a different PID; $BASHPID is the real one)
$?    # Exit status of the most recently run command (0 = success)
$#    # Count of positional arguments
$@    # All positional arguments (always quote it: "$@")
$1 $2 # Positional arguments - bash has no named parameters
```

Bash does not evaluate expressions to true/false — it works off exit codes.

## Default values

```bash
number="${1:-0}"   # Use $1 if it is set, otherwise 0
```

No spaces around `=` in an assignment — `number = ...` tries to run a command called `number`.

## Test operators

| Test | Meaning |
| --- | --- |
| `-e` | path exists |
| `-f` | regular file |
| `-d` | directory |
| `-L` | symbolic link |
| `-S` | socket |
| `-r` / `-w` / `-x` | readable / writable / executable |
| `-z` / `-n` | string empty / non-empty |
| `-eq` `-ne` `-lt` `-le` `-gt` `-ge` | numeric comparison |

```bash
if [[ -f /proc/1/status ]]; then
    echo "exists"
fi
```

## Inspecting commands

```bash
type <command>   # Says whether it is a builtin, keyword, alias, function, or a path on disk
```

## Redirection

The direction of the arrow is the direction the data flows.

```bash
command > abc.txt     # stdout to file, overwrites
command >> abc.txt    # stdout to file, appends
command < abc.txt     # file as stdin
command 2> err.txt    # stderr to file
command > out.txt 2>&1 # stdout to file, then stderr to wherever stdout points
command | other       # pipe stdout into another command
```

File descriptors: `0` = stdin, `1` = stdout, `2` = stderr. Use `&` to say "this number is a
file descriptor, not a filename" — `2>&1` vs `2>1` (the latter writes to a file named `1`).

Order matters: `> out.txt 2>&1` redirects both, `2>&1 > out.txt` sends stderr to the
*original* stdout and only stdout to the file.

## Forks

Runs in a child process:

1. `( ... )` — explicit subshell
2. `$( ... )` and backticks — command substitution
3. Pipelines `cmd1 | cmd2` — each stage in its own subshell (the last stage stays in the current shell if `shopt -s lastpipe` is set in a non-interactive script)
4. Background jobs — `cmd &`
5. Process substitution — `<( ... )` and `>( ... )`
6. Coprocesses — `coproc { ... }`

### Forks + execs (an external program replaces the child)

1. Any external binary — `ls`, `grep`, `ps`, `python3`, `date`
2. Subshells that call external programs — `$(ls)` forks for the subshell, then forks+execs for `ls`

### Does NOT fork — stays in the current process

1. `{ ... }` group commands
2. `if`/`elif`/`else`, `while`/`until`, `for`, `case` — pure control flow
3. Function calls invoked plainly (`myfunc arg1`), not wrapped in `$( )`
4. Builtins — `echo`, `read`, `cd`, `export`, `local`, `printf`, `test` / `[[ ]]` / `[ ]`, `let`, `:`, `source` / `.`, `shift`, `unset`, `exit`, `return`, `type`, `trap`
5. Variable assignment — `x=1`
6. Redirections — `< file`, `> file`, `2>&1`
7. Arithmetic expansion — `$(( ... ))`

## Special file paths

- `/dev/null` — the bit bucket. Anything written to it vanishes; reading it returns EOF immediately. Used to suppress stdout or stderr.

## Other quirks

1. Always quote your variables — unquoted expansion breaks silently on spaces and globs.
2. Functions have no named parameters; use `$1`, `$2`, ...
3. Functions do not return values, only exit codes. To "return" a value, `echo` it and capture with `$( )`.
4. Variables are global by default — use `local` inside functions.
5. `set -euo pipefail` at the top of a script: exit on error, exit on unset variable, fail a pipeline if any stage fails.
