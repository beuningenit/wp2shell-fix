#!/bin/bash
set -uo pipefail

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
. "$REPO_ROOT/lib/common.sh"
. "$REPO_ROOT/config/wp2shell.conf"
. "$REPO_ROOT/lib/version.sh"
. "$REPO_ROOT/lib/discovery.sh"
. "$REPO_ROOT/lib/backup.sh"
. "$REPO_ROOT/lib/quarantine.sh"
. "$REPO_ROOT/lib/harden.sh"
. "$REPO_ROOT/lib/clean.sh"

detect_optional_commands
resolve_external_tools >/dev/null 2>&1

tests_run=0
tests_failed=0

expect_equal() {
    local label=$1 expected=$2 actual=$3
    tests_run=$((tests_run + 1))
    if [ "$expected" = "$actual" ]; then
        printf 'ok   %s\n' "$label"
    else
        printf 'FAIL %s: verwacht "%s", kreeg "%s"\n' "$label" "$expected" "$actual" >&2
        tests_failed=$((tests_failed + 1))
    fi
}

FIXTURE=$(mktemp -d -t wp2shell-ctest.XXXXXXXX)
trap 'rm -rf -- "$FIXTURE"' EXIT

WP2SHELL_RUN_ID="testrun"
WP2SHELL_QUARANTINE_DIR="$FIXTURE/quarantine"
WP2SHELL_BACKUP_DIR="$FIXTURE/backups"
WP2SHELL_FINDINGS_FILE="$FIXTURE/findings.ndjson"
WP2SHELL_AUDIT_LOG="$FIXTURE/audit.log"

SITE="$FIXTURE/site"
mkdir -p "$SITE/wp-content/uploads" "$SITE/wp-includes"
printf '<?php kwaadaardig\n' > "$SITE/wp-content/uploads/shell.php"
printf '<?php heuristisch base64_decode\n' > "$SITE/wp-content/uploads/twijfel.php"
printf '<?php eigen maatwerk\n' > "$SITE/wp-content/uploads/maatwerk.php"

write_finding() {
    local category=$1 confidence=$2 file=$3
    : > /dev/null
    record_finding \
        "site=$SITE" \
        "severity=$SEVERITY_CRITICAL" \
        "confidence=$confidence" \
        "category=$category" \
        "title=testbevinding" \
        "detail=test" \
        "file=$file"
}

: > "$WP2SHELL_FINDINGS_FILE"
write_finding "php-in-writable-directory" "$CONFIDENCE_HIGH" "$SITE/wp-content/uploads/shell.php"
write_finding "obfuscation" "$CONFIDENCE_HEURISTIC" "$SITE/wp-content/uploads/twijfel.php"
write_finding "php-in-writable-directory" "$CONFIDENCE_HIGH" "$SITE/wp-content/uploads/maatwerk.php"

WP2SHELL_ALLOWLIST_PATHS=("$SITE/wp-content/uploads/maatwerk.php")

quarantine_findings_for_site "$SITE" "$(id -un)" 0 >/dev/null 2>&1
expect_equal "zonder --apply blijft het kwaadaardige bestand staan" "ja" \
    "$([ -f "$SITE/wp-content/uploads/shell.php" ] && printf 'ja' || printf 'nee')"

quarantine_findings_for_site "$SITE" "$(id -un)" 1 >/dev/null 2>&1
expect_equal "met --apply gaat de bevestigde webshell in quarantaine" "nee" \
    "$([ -f "$SITE/wp-content/uploads/shell.php" ] && printf 'ja' || printf 'nee')"
expect_equal "het heuristische bestand blijft staan" "ja" \
    "$([ -f "$SITE/wp-content/uploads/twijfel.php" ] && printf 'ja' || printf 'nee')"
expect_equal "het bestand op de allowlist blijft staan" "ja" \
    "$([ -f "$SITE/wp-content/uploads/maatwerk.php" ] && printf 'ja' || printf 'nee')"

expect_equal "categorie zonder auto-actie wordt niet verplaatst" "nee" \
    "$(category_is_auto_quarantinable "obfuscation" && printf 'ja' || printf 'nee')"
expect_equal "bekende kwaadaardige categorie is wel auto-actionable" "ja" \
    "$(category_is_auto_quarantinable "known-malware-hash" && printf 'ja' || printf 'nee')"

BACKUP_SITE="$FIXTURE/site2"
mkdir -p "$BACKUP_SITE/wp-content/uploads" "$BACKUP_SITE/wp-includes"
printf '<?php kwaadaardig twee\n' > "$BACKUP_SITE/wp-content/uploads/shell2.php"
: > "$WP2SHELL_FINDINGS_FILE"
record_finding \
    "site=$BACKUP_SITE" \
    "severity=$SEVERITY_CRITICAL" \
    "confidence=$CONFIDENCE_HIGH" \
    "category=php-in-writable-directory" \
    "title=testbevinding" \
    "detail=test" \
    "file=$BACKUP_SITE/wp-content/uploads/shell2.php"

WP2SHELL_BACKUP_DIR="$BACKUP_SITE/backups"
clean_site "$BACKUP_SITE" "$(id -un)" 1 0 0 "" >/dev/null 2>&1
CLEAN_RC=$?
expect_equal "clean stopt wanneer de backuplocatie onveilig is" "1" "$CLEAN_RC"
expect_equal "er is niets opgeschoond zonder geslaagde backup" "ja" \
    "$([ -f "$BACKUP_SITE/wp-content/uploads/shell2.php" ] && printf 'ja' || printf 'nee')"
expect_equal "de mislukte backup is gerapporteerd" "1" \
    "$("${WP2SHELL_GREP:-grep}" -c 'backup-failed' "$WP2SHELL_FINDINGS_FILE" || true)"

EMITTED=$(mktemp)
{
    "${WP2SHELL_GREP:-grep}" -ohE '"category=[a-z0-9-]+"' "$REPO_ROOT"/lib/detect_*.sh \
        | sed 's/"category=//; s/"//'
    "${WP2SHELL_GREP:-grep}" -ohE '^[[:space:]]*category="[a-z0-9-]+"' "$REPO_ROOT"/lib/detect_*.sh \
        | sed 's/.*category="//; s/"//'
} | sort -u > "$EMITTED"

for category in "${WP2SHELL_AUTO_QUARANTINE_CATEGORIES[@]}"; do
    tests_run=$((tests_run + 1))
    if "${WP2SHELL_GREP:-grep}" -qx "$category" "$EMITTED"; then
        printf 'ok   auto-quarantaine categorie %s wordt echt uitgegeven\n' "$category"
    else
        printf 'FAIL categorie %s staat in de auto-quarantainelijst maar geen enkele detectiemodule geeft die uit\n' "$category" >&2
        tests_failed=$((tests_failed + 1))
    fi
done
rm -f -- "$EMITTED"

STRUCTURE_REPORT=$(php "$REPO_ROOT/tools/check_completion_markers.php" "$REPO_ROOT/lib/detect_wp.sh")
expect_equal "elk afgehandeld returnpad meldt zich af als voltooid" "" "$STRUCTURE_REPORT"

printf '\n%s tests, %s mislukt\n' "$tests_run" "$tests_failed"
if [ "$tests_failed" -gt 0 ]; then
    exit 1
fi
