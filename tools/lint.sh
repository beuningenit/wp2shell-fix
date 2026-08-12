#!/bin/bash
set -euo pipefail

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

SHELLCHECK_BIN=${SHELLCHECK_BIN:-shellcheck}
SHELLCHECK_EXCLUDES=SC1090,SC1091,SC2016,SC2029,SC2034,SC2254,SC2329

failures=0

if ! command -v "$SHELLCHECK_BIN" >/dev/null 2>&1; then
    printf 'shellcheck niet gevonden, zet SHELLCHECK_BIN of installeer shellcheck\n' >&2
    exit 2
fi

printf 'Shellcheck\n'
while IFS= read -r -d '' file; do
    if ! "$SHELLCHECK_BIN" -s bash -e "$SHELLCHECK_EXCLUDES" "$file"; then
        failures=$((failures + 1))
    fi
done < <(find . -type f -name '*.sh' -not -path './.git/*' -print0 2>/dev/null)

printf 'Controle op em dash en en dash\n'
if grep -rInP '[\x{2014}\x{2013}]' --include='*.sh' --include='*.md' --include='*.conf' --include='*.txt' . ; then
    printf 'Em dash of en dash aangetroffen, dat is niet toegestaan\n' >&2
    failures=$((failures + 1))
fi

printf 'Controle op commentaarregels in scripts\n'
while IFS= read -r -d '' file; do
    offending=$(grep -nE '^[[:space:]]*#' "$file" | grep -vE '^1:#!/bin/bash' || true)
    if [ -n "$offending" ]; then
        printf '%s bevat commentaarregels:\n%s\n' "$file" "$offending" >&2
        failures=$((failures + 1))
    fi
done < <(find . -type f -name '*.sh' -not -path './.git/*' -print0 2>/dev/null)

if [ "$failures" -gt 0 ]; then
    printf 'Lint mislukt met %s probleem(en)\n' "$failures" >&2
    exit 1
fi

printf 'Lint geslaagd\n'
