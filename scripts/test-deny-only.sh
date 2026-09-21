#!/usr/bin/env bash
# =============================================================================
# test-deny-only.sh - stage 1: the same payloads as test-hook.sh, judged by
# permissions.deny ALONE. No hook runs here.
#
# The verdict comes from a local model of Claude Code's own rule matching
# (docs: /docs/en/permissions):
#     Bash(cmd:*)   prefix match, per subcommand, on the text as written
#     Bash(cmd)     exact match on the subcommand
#     Read(path)    gitignore-style path match, relative to the project root
#                   (applies to Read / Glob / Grep / NotebookEdit)
#
# It never looks inside quotes, never rewrites /bin/cat to cat, and never
# expands a glob - the deny list sees the spelling, not the intent. That is the
# whole demo. Run this, then run ./scripts/test-hook.sh and compare.
#
# Payload rows and group headers are eval'd straight out of test-hook.sh, so
# the two demos cannot drift apart.
#
#     ./scripts/test-deny-only.sh [settings.json]
# =============================================================================
set -uo pipefail
PROJ="$(cd "$(dirname "$0")/.." && pwd)"
SETTINGS="${1:-$PROJ/.claude/settings.json}"
G='\033[32m'; RED='\033[31m'; Y='\033[33m'; D='\033[2m'; N='\033[0m'

BASH_RULES=$(jq -r '.permissions.deny[] | select(startswith("Bash(")) | .[5:-1]' "$SETTINGS")
READ_RULES=$(jq -r '.permissions.deny[] | select(startswith("Read(")) | .[5:-1]' "$SETTINGS")
DENIED=0; ALLOWED=0

# Split on unquoted ; | & && || - Claude Code matches each part separately.
subcommands() {
  awk '{ q=""; s="";
    for (i=1; i<=length($0); i++) { c=substr($0,i,1)
      if (q != "")                  { s = s c; if (c == q) q="" }
      else if (c=="\"" || c=="'\''"){ q=c; s = s c }
      else if (c=="|"||c=="&"||c==";") { print s; s="" }
      else                          { s = s c } }
    print s }' <<<"$1" | sed -E 's/^ +| +$//g' | grep -v '^$'
}

bash_denied() {
  local sub rule prefix
  while IFS= read -r sub; do
    while IFS= read -r rule; do
      [ -z "$rule" ] && continue
      case "$rule" in
        *:\*) prefix="${rule%:\*}"
              case "$sub" in "$prefix"|"$prefix "*) HIT="Bash($rule)"; return 0 ;; esac ;;
        *)    [ "$sub" = "$rule" ] && { HIT="Bash($rule)"; return 0; } ;;
      esac
    done <<<"$BASH_RULES"
  done < <(subcommands "$1")
  return 1
}

# ponytail: collapses x/../ only; a leading ../ is left alone and so reads as
# outside the project, which is the answer we want for it anyway.
norm() {
  local p="$1"
  while printf '%s' "$p" | grep -qE '(^|/)[^/]+/\.\./'; do
    p=$(printf '%s' "$p" | sed -E 's#(^|/)[^/]+/\.\./#\1#')
  done
  printf '%s' "$p"
}

file_denied() {
  local p="${1#./}" abs rel rule pat
  case "$p" in /*) abs="$p" ;; *) abs="$PROJ/$p" ;; esac
  abs=$(norm "$abs")
  # A path outside the project matches no ./-anchored rule at all.
  case "$abs" in "$PROJ"/*) rel="${abs#"$PROJ"/}" ;; *) return 1 ;; esac
  while IFS= read -r rule; do
    [ -z "$rule" ] && continue
    pat="${rule#./}"
    case "$pat" in
      */\*\*) case "$rel" in "${pat%/\*\*}"/*) HIT="Read($rule)"; return 0 ;; esac ;;
      *)      [ "$rel" = "$pat" ] && { HIT="Read($rule)"; return 0; } ;;
    esac
  done <<<"$READ_RULES"
  return 1
}

row() {
  HIT=""
  case "$1" in
    Read|Notebook) file_denied "$2" ;;
    *)             bash_denied "$2" ;;
  esac
  if [ -n "$HIT" ]; then
    DENIED=$((DENIED + 1))
    printf "  ${RED}%-10s${N} ${D}%-20s${N} %-50s ${D}%s${N}\n" "DENY" "$3" "$2" "$HIT"
  else
    ALLOWED=$((ALLOWED + 1))
    printf "  ${G}%-10s${N} ${D}%-20s${N} %s\n" "allowed" "$3" "$2"
  fi
}

while IFS= read -r line; do
  eval "$line"
done < <(grep -E '^(row |echo$|echo -e "\$\{Y\}== )' "$PROJ/scripts/test-hook.sh")

printf "  ${D}deny list alone: %d denied, %d allowed, of %d payloads.${N}\n" \
  "$DENIED" "$ALLOWED" "$((DENIED + ALLOWED))"
printf "  ${D}Same payloads through the stage 2 hook: run ./scripts/test-hook.sh.\n"
printf "  Blocks 5, 10 and 11 are meant to pass; every other allowed row is a leak.${N}\n\n"
