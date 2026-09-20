#!/usr/bin/env bash
# =============================================================================
# deny-guard.sh - PreToolUse hook for Claude Code
# Conf42 DevSecOps 2026 - "When AI Ignores the Deny List"
#
# WHY THIS EXISTS
#   permissions.deny matches the command text Claude writes, one subcommand at
#   a time. The docs say it plainly: a Bash deny rule "isn't a security boundary
#   around the program". Bash(rm:*) stops `rm -rf x` and not `/bin/rm -rf x`.
#   Read(./.env) stops `cat .env` and not `python3 -c "print(open('.env').read())"`.
#
#   This hook sees the FULL, RAW command string before it runs, normalises it,
#   and matches on intent instead of on spelling.
#
# CONTRACT (docs: /docs/en/hooks)
#   stdin  : JSON { tool_name, tool_input: { command | file_path | path }, ... }
#   stdout : { "hookSpecificOutput": { "hookEventName": "PreToolUse",
#              "permissionDecision": "deny"|"ask"|"allow",
#              "permissionDecisionReason": "..." } }
#   exit 0 : JSON decision is honoured - the intended code for structured output.
#   exit 2 : blocks regardless of JSON; even a JSON "allow" cannot override it.
#   exit 1 : with valid JSON the exit code is IGNORED and the JSON decides;
#            with no valid JSON it is a non-blocking error and the tool RUNS.
#            The docs: "if your hook is meant to enforce a policy, use exit 2."
#   A wrong script path exits 127 - also non-blocking. Check your first run.
#
#   A hook cannot loosen a deny rule: Claude Code evaluates deny/ask rules no
#   matter what this returns. It tightens in the other direction too - a hook
#   exiting 2 stops the call BEFORE permission rules run, beating an allow rule.
#   Valid permissionDecision values: "allow", "deny", "ask".
# =============================================================================
set -uo pipefail

INPUT=$(cat)
TOOL=$(printf '%s' "$INPUT" | jq -r '.tool_name // empty')
CMD=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty')
# docs: file_path for Read/Edit/Write, path for Grep/Glob, notebook_path for NotebookEdit
FILE=$(printf '%s' "$INPUT" | jq -r '.tool_input.file_path // .tool_input.path // .tool_input.notebook_path // empty')

deny() {
  jq -n --arg r "deny-guard: $1" \
    '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$r}}'
  exit 0
}

# --- paths that must never be read, written, or named on a command line ------
SECRET_RE='(^|[^A-Za-z0-9_.-])\.env([.][A-Za-z0-9_.-]+)?([^A-Za-z0-9_.-]|$)|(^|/)secrets/|\.ssh/id_|\.pem([^A-Za-z0-9]|$)|\.aws/credentials|\.config/gcloud/|\.azure/|\.gnupg/|Library/Keychains|\.netrc|\.npmrc|id_rsa|id_ed25519|\.bash_history|\.zsh_history|(Cookies|Login Data)|cookies\.sqlite|logins\.json'

# =============================================================================
# FILE TOOLS  (Read / Edit / Write / Glob / Grep)
# =============================================================================
if [ -n "$FILE" ]; then
  if printf '%s' "$FILE" | grep -qE "$SECRET_RE"; then
    deny "'$FILE' is a protected path"
  fi
  exit 0
fi

[ -z "$CMD" ] && exit 0

# =============================================================================
# NORMALISE  - this is the whole trick.
#   1. strip quotes        ->  git 'push'      becomes  git push
#                              sh -c 'cat .env' becomes sh -c cat .env
#   2. strip binary dirs   ->  /bin/rm         becomes  rm
#   3. collapse whitespace ->  rm    -rf       becomes  rm -rf
# Match the NORMALISED string, not what the model typed.
# =============================================================================
N=$(printf '%s' "$CMD" \
  | tr -d "\"'" \
  | sed -E 's#(^|[[:space:];&|(])/(usr/local/|usr/|opt/homebrew/|opt/local/)?s?bin/#\1#g' \
  | tr -s '[:space:]' ' ')

check() { printf '%s' "$N" | grep -qE "$1" && deny "$2"; return 0; }

# --- 1. any mention of a protected path, by ANY program ----------------------
check "$SECRET_RE" "command references a protected path (.env / secrets / keys)"

# --- 2. arbitrary code eval: the hook cannot see inside the string ------------
check '\b(python3?|node|deno|bun|ruby|perl|php)\b[^|;&]*\s-(c|e)\b' \
      "inline script eval is denied - a script can open any file without naming it"

# --- 3. environment runners that Claude Code does NOT strip before matching ---
#        docs: npx / docker exec / devbox run / mise exec / direnv exec
check '\b(docker\s+(exec|run)|devbox\s+run|direnv\s+exec|mise\s+exec|npx|pnpm\s+dlx|yarn\s+dlx)\b' \
      "environment runner is denied - it executes an inner command the deny rules never see"

# --- 4. shell re-entry: sh -c / bash -c / eval / pipe-to-shell ----------------
check '\b(sh|bash|zsh|dash|ksh)\s+-c\b' "nested shell (-c) is denied"
check '\beval\b'                        "eval is denied"
check '\|\s*(sh|bash|zsh)\b'            "piping into a shell is denied"
check '<\s*\(|\$\(\s*(curl|wget)'       "process substitution of a download is denied"

# --- 5. readers that never name the file ------------------------------------
check '\bgrep\b[^|;&]*\s-[A-Za-z]*r'    "recursive grep is denied - it reads denied files without naming them"
check '\bfind\b[^|;&]*\s-(exec|delete)' "find -exec / -delete is denied"
check '\btar\b[^|;&]*\s-?c'             "tar create is denied - it can package a denied path"
check '\b(xxd|od|strings|base64|hexdump|rev|shred)\b' "binary/encoding reader is denied"

# --- 6. destructive ----------------------------------------------------------
check '(^| )rm( |$)'                    "rm is denied"
check '\brmdir\b'                       "rmdir is denied"
check '\bsudo\b'                        "sudo is denied"
check 'git\s+push\b'                    "git push is denied"
check 'git\s+(-C|-c)\b[^|;&]*\bpush\b'  "git push via -C/-c is denied"
check 'git\s+reset\b[^|;&]*--hard'      "git reset --hard is denied"
check 'git\s+clean\b[^|;&]*-[A-Za-z]*[fd]' "git clean -fd is denied"
check 'git\s+branch\b[^|;&]*-D'         "git branch -D is denied"

# --- 7. outbound network (exfiltration) --------------------------------------
check '\b(curl|wget|nc|ncat|socat|telnet)\b' "outbound network tool is denied"

exit 0
