# The bypass cheat sheet

Every claim below is tagged with its evidence. **[DOC]** = stated in Anthropic's
documentation, quoted. **[INFER]** = follows from a documented rule but is not
itself stated; verify on your own machine before asserting it on stage.

Sources: `code.claude.com/docs/en/permissions`, `/en/hooks`, `/en/settings`,
`/en/managed-settings`, `/en/github-actions`, `/en/tools-reference`.

## The thesis [DOC]

> A Bash rule matches the command text Claude writes ... It doesn't match the
> same program invoked in a different form, so a deny or ask rule covers the
> invocation Claude usually produces and **isn't a security boundary around the
> program.**

> Read and Edit deny rules apply to Claude's built-in file tools, to file
> commands Claude Code recognizes in Bash, such as `cat`, `head`, `tail`,
> `sed`, and `tee`, and to the targets of Bash redirections such as `> file`
> and `< file`. **They don't apply to a command that reads files without naming
> them**, such as `grep -r pattern .` run from the directory that holds the
> file, **or to arbitrary subprocesses that read or write files indirectly,
> like a Python or Node script that opens files itself.**

## What deny DOES catch — do not claim otherwise on stage [DOC]

> Deny and ask rules apply when any subcommand matches them, including a
> command nested inside a subshell, a command substitution, or a control-flow
> body such as a `for` loop.

Recognized separators: `&&  ||  ;  |  |&  &` and newlines.

    cd /tmp && rm -rf x          <- caught
    echo "$(rm -rf x)"           <- caught
    for f in *; do rm $f; done   <- caught
    FOO=bar rm -rf tmp/          <- caught ("A deny or ask rule matches past any
                                    leading assignment")
    timeout 30 rm -rf x          <- caught (timeout, time, nice, nohup, stdbuf,
                                    command, builtin, noglob are stripped first)

The parser is not the problem. **The rule is a string match on one spelling of
a program, and a program has unlimited spellings.**

## What deny MISSES

### Documented verbatim in the docs' own table [DOC]

| Rule | Stops | Does NOT stop |
|------|-------|---------------|
| `Bash(curl *)` | `curl https://example.com` | `/usr/bin/curl https://example.com`, `sh -c 'curl https://example.com'` |
| `Bash(rm *)` | `rm -rf build/` | `/bin/rm -rf build/`, `bash -c 'rm -rf build/'` |
| `Bash(git push *)` | `git push origin main` | `git -C . push origin main`, `git -c push.default=current push origin main`, `git 'push' origin main` |

### Documented in prose [DOC]

- **Indirect reads.** `python3 -c "print(open('.env').read())"` and
  `node -e "...readFileSync('.env')"` — "arbitrary subprocesses that read or
  write files indirectly".
- **Unnamed reads.** `grep -r CONF42_FLAG .` — named in the docs by example.
- **Environment runners.** `npx`, `docker exec`, `devbox run`, `mise exec`,
  `direnv exec` are **not** in the stripped-wrapper list, and "because these
  tools execute their arguments as a command, a rule like `Bash(devbox run *)`
  matches whatever comes after `run`, including `devbox run rm -rf .`"
- **Exec wrappers.** `watch`, `setsid`, `ionice`, `flock`, and `find` with
  `-exec` or `-delete` are not covered by a prefix rule.
- **Over-broad allow rules.** In `Bash(git * main)` the `*` "stands in for the
  subcommand, so Claude Code matches every git subcommand and every option
  before it. **That includes `-c`, which makes git run a program you name.**"
- **Missing space.** "`Bash(ls *)` requires a space after `ls`, so `lsof`
  doesn't match. `Bash(ls*)` has no space, so it matches `lsof` too."
- **Argument constraints are fragile.** `Bash(curl http://github.com/ *)` does
  not match `curl -X GET http://github.com/...`, an https URL, a redirect, or
  `URL=http://github.com && curl $URL`.

### Follows from the above but is NOT separately documented [INFER]

- `/bin/cat .env` and `sh -c 'cat .env'` defeat a **`Bash(cat:*)`** rule — that
  much is the documented table. Whether they also defeat a **`Read(./.env)`**
  rule depends on whether Claude Code still recognizes `cat` through an
  absolute path or a nested shell. The docs don't say. Test it yourself.
- `awk`, `base64`, `xxd`, `strings`, `od` as file readers. The recognized list
  is given as "such as `cat`, `head`, `tail`, `sed`, and `tee`" — non-exhaustive,
  so any of these may or may not be recognized. Test before claiming.
- `tar cf - secrets/` against a `Read(./secrets/**)` rule. Same reason.

The point stands either way: column three is infinite and you cannot enumerate
your way out of it.

## Red-teaming the hook itself  [TESTED]

`deny-guard.sh` was attacked the same way the deny list was. Two gaps, and they
are different in kind. This distinction is the real lesson.

### Reads: the hook anchored on names, so a name got past it  [FIXED]

`kubeconfig.demo` walked straight through, because "kubeconfig" was not in
`SECRET_RE`. The mechanism was fine - `SECRET_RE` runs on every command and
every file-tool path, so `awk`, `sed`, `tail` and `/bin/cat` are all caught the
moment the path matches - but the *list* was short.

Widened to cover kubeconfig, `.kube/`, tfstate/tfvars, `credentials.yaml|json`,
service-account JSON, p12/pfx/key/keystore/jks, `id_dsa`, `id_ecdsa`,
`docker/config.json`, `.dockercfg`.

**And, more importantly, stopped relying on names alone.** File-tool paths are
now checked by *location*: a path containing `..` is denied, and a path that
resolves outside the session's `cwd` is denied. A name list never ends; "inside
the project or not" does not grow. Names remain as a second line of defence for
the secrets that live inside the project.

### Deletes: unwinnable in a hook, and worth saying so  [BY DESIGN]

`rm`, `rmdir` and `find -delete` were covered. These destroyed files anyway:

    dd of=file        truncate -s0 file      install /dev/null file
    cp /dev/null file                                                  <- now blocked

    > file            : > file               mv file away
                                                                       <- still open

The first four are now checked. The last three are **not**, deliberately:

- Blocking `>` means blocking all output redirection.
- Blocking `mv` means blocking refactoring.

"Make a file disappear" has unbounded spellings. That is the same
enumerate-badness treadmill as the deny list, one level up - this time in *my*
code. A command string is the wrong place to win it.

### Round 3: a glob beat the hook, found by the guarded CI run  [TESTED]

`02-hook-guarded.yml` was supposed to block every route. It blocked the Read
tool, it blocked `ls -R`, and `deny-guard.sh` blocked `git show HEAD:.env` when
`SECRET_RE` matched. Then this got the file:

    head -n 50 .e*

The shell expands `.e*` to `.env` **after** the permission check and after the
hook, so nothing in the chain ever sees the literal string `.env`:

- `Read(./.env)` matches the literal path `.env`, not the glob `.e*`.
- `SECRET_RE` needs a literal `\.env`; `.e*` has no `.env` substring.
- `head` is not on any reader list, and adding it would not help - the next
  reader would not be on the list either.

Claude's own summary from that run: *"The name-anchored controls can't enumerate
every spelling; a shell glob is one more spelling."*

**Fixed** by rejecting a token that starts with a literal `.` and contains a glob
metacharacter. Only a pattern whose first character is a literal dot can expand
to a dotfile - bash does not match leading dots with `*` or `?` unless `dotglob`
is set - so the rule stays narrow. It also rejects `ls .*`, which is harmless but
legitimate; for a guard hook that is the right side to err on.

This is the third time this hook has been patched for the same reason: it
anchored on a name, and someone found another spelling. Each fix was correct and
each one was late. That is the argument for the sandbox, not against the hook.

### The rule this gives you

| goal | anchor on | can a hook win? |
|------|-----------|-----------------|
| stop a **read** | the data: path and location | Yes, if you anchor on location rather than names |
| stop a **delete or write** | the program | No. Unbounded spellings |

For writes and deletes the fix is below the agent: a container, a separate user,
or the sensitive paths mounted read-only. Run `./scripts/test-hook.sh` and look
at block 8 - the hook reports its own failures.

## What actually holds

1. **PreToolUse hook** — sees the full raw command string. `deny-guard.sh` here.
2. **Sandboxing** — "For OS-level enforcement that blocks all processes from
   accessing a path, enable the sandbox." The only thing that stops a rogue
   subprocess. [DOC]
3. **Managed settings** — so 1 and 2 are not the developer's choice.

## Hook precedence — both directions [DOC]

> Hook decisions don't bypass permission rules. Claude Code evaluates deny and
> ask rules regardless of what a PreToolUse hook returns: a matching deny rule
> blocks the call, and a matching ask rule still prompts even when the hook
> returned `"allow"` or `"ask"`.

> A blocking hook also takes precedence over allow rules. A hook that exits
> with code 2 stops the tool call **before permission rules are evaluated**, so
> the block applies even when an allow rule would otherwise let the call
> proceed.

So the hook can always tighten, and can never loosen. `"allow"`, `"deny"` and
`"ask"` are all valid `permissionDecision` values.

## Hook exit codes — the real rules [DOC]

| exit | stdout | effect |
|------|--------|--------|
| 0 | valid JSON decision | honored — "the intended exit code when you print JSON for structured control" |
| 2 | anything | **blocks** — "exit 2 blocks whether or not you print JSON: even a JSON `permissionDecision` of `"allow"` can't override it" |
| 1 (or any other) | valid JSON decision | "Claude Code **ignores the exit code** and the JSON alone decides the outcome" |
| 1 (or any other) | no valid JSON | **does not block** — the action proceeds |

The warning to quote:

> Without valid JSON on stdout, Claude Code treats exit code 1 as a
> non-blocking error and proceeds with the action, even though 1 is the
> conventional Unix failure code. If your hook is meant to enforce a policy,
> use `exit 2`.

Also worth knowing: a hook whose script path is wrong exits 127 and is treated
as non-blocking — **"a mistyped path in `settings.json` leaves the gate
silently disabled."** And on PreToolUse, a command hook that hits its `timeout`
**does not block**: "don't count on a stalled hook to act as a gate."

## Tool input field names [DOC]

> `command` for Bash and PowerShell, `file_path` for Read, Edit, and Write,
> `path` for Grep and Glob, `notebook_path` for NotebookEdit, and `url` for
> WebFetch.

A guard hook on file tools must read all three path fields. `deny-guard.sh` does.

## Matcher syntax [DOC]

A matcher of only letters, digits, `_`, `-`, spaces, `,` and `|` is an exact
string or a `|`/`,`-separated list of exact strings. Anything else is an
**unanchored** JavaScript regex — `Edit.*` also matches `NotebookEdit`, so
anchor with `^Edit$` when you mean one tool.

## Settings precedence [DOC]

1. Managed settings (`managed-settings.json`, MDM, or server-managed)
2. Command line (`claude --settings`)
3. Project local (`.claude/settings.local.json`)
4. Shared project (`.claude/settings.json`)
5. User (`~/.claude/settings.json`)

Managed settings cannot be loosened from below. They are not absolute in the
other direction: "For a few security-sensitive keys, Claude Code honors a
stricter value from a lower level over a managed value."

And note: **list keys merge rather than override.** "When you set the same list
key, such as `permissions.allow`, in more than one file, Claude Code combines
the lists." A project file can add allow entries; it cannot remove a managed
deny entry.
