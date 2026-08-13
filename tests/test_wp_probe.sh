#!/bin/bash
set -uo pipefail

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
. "$REPO_ROOT/lib/common.sh"
. "$REPO_ROOT/config/wp2shell.conf"
. "$REPO_ROOT/lib/version.sh"
. "$REPO_ROOT/lib/discovery.sh"
. "$REPO_ROOT/lib/detect_wp.sh"

tests_run=0
tests_failed=0

expect_contains() {
    local label=$1 needle=$2 haystack=$3
    tests_run=$((tests_run + 1))
    case $haystack in
        *"$needle"*) printf 'ok   %s\n' "$label" ;;
        *)
            printf 'FAIL %s: "%s" ontbreekt in "%s"\n' "$label" "$needle" "$haystack" >&2
            tests_failed=$((tests_failed + 1))
            ;;
    esac
}

WORKROOT=$(mktemp -d)
trap 'rm -rf -- "$WORKROOT"' EXIT

probe="$WORKROOT/probe.out"

printf 'Error: De database is niet bereikbaar.\n' > "$probe"
expect_contains "foutregel van WP-CLI wordt overgenomen" \
    "De database is niet bereikbaar" "$(wp_probe_failure_reason "$probe" 1)"

printf 'PHP Warning: iets onbelangrijks\nError: wp-config.php ontbreekt\n' > "$probe"
expect_contains "php-waarschuwing wordt overgeslagen" \
    "wp-config.php ontbreekt" "$(wp_probe_failure_reason "$probe" 1)"

: > "$probe"
expect_contains "exitcode 127 wijst naar het pad" \
    "php of WP-CLI niet in het pad" "$(wp_probe_failure_reason "$probe" 127)"
expect_contains "exitcode 126 wijst naar rechten" \
    "sudo en de rechten" "$(wp_probe_failure_reason "$probe" 126)"
expect_contains "exitcode 124 wijst naar de tijdslimiet" \
    "tijdslimiet" "$(wp_probe_failure_reason "$probe" 124)"
expect_contains "exitcode 1 zonder uitvoer blijft benoemd" \
    "zonder foutregel" "$(wp_probe_failure_reason "$probe" 1)"
expect_contains "onbekende exitcode wordt genoemd" \
    "exitcode 42" "$(wp_probe_failure_reason "$probe" 42)"

rm -f -- "$probe"
expect_contains "ontbrekend bestand levert nog steeds een duiding" \
    "exitcode 3" "$(wp_probe_failure_reason "$probe" 3)"

head -c "${WP2SHELL_PROBE_CAPTURE_MAX_BYTES:-65536}" /dev/zero | tr '\0' 'A' > "$probe"
expect_contains "een volgelopen opvangbestand wordt als afkapping geduid" \
    "afgekapt op" "$(wp_probe_failure_reason "$probe" 13)"

SPUIT="$WORKROOT/wp-spuit"
cat > "$SPUIT" <<'SPUITEOF'
#!/bin/bash
while :; do printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; done
SPUITEOF
chmod 0755 -- "$SPUIT"
spuit_capture="$WORKROOT/spuit.out"
spuit_status=0
(
    WP2SHELL_WP_CLI_RESOLVED="$SPUIT"
    wp_is_functional "$(id -un)" "$WORKROOT" "$spuit_capture"
) || spuit_status=$?
spuit_bytes=$(stat -c '%s' -- "$spuit_capture" 2>/dev/null) || spuit_bytes=0
tests_run=$((tests_run + 1))
if [ "$spuit_status" -ne 0 ] && [ "$spuit_bytes" -le "${WP2SHELL_PROBE_CAPTURE_MAX_BYTES:-65536}" ]; then
    printf 'ok   eindeloze uitvoer wordt begrensd op %s bytes\n' "$spuit_bytes"
else
    printf 'FAIL eindeloze uitvoer werd niet begrensd: status %s, %s bytes\n' "$spuit_status" "$spuit_bytes" >&2
    tests_failed=$((tests_failed + 1))
fi

SITE="$WORKROOT/home/klant/domains/a.nl/public_html"
mkdir -p "$SITE/wp-includes" "$SITE/wp-admin" "$SITE/wp-content/plugins" "$SITE/wp-content/themes"
printf '<?php\n$table_prefix = "wp_";\n' > "$SITE/wp-config.php"
printf '<?php\n' > "$SITE/wp-load.php"
printf '<?php $wp_version = "7.0.3";\n' > "$SITE/wp-includes/version.php"

STUB="$WORKROOT/wp-stuk"
cat > "$STUB" <<'STUBEOF'
#!/bin/bash
printf 'Error: Kon geen verbinding maken met de databaseserver.\n' >&2
exit 1
STUBEOF
chmod 0755 -- "$STUB"

detect_optional_commands >/dev/null 2>&1
resolve_external_tools >/dev/null 2>&1

FINDINGS="$WORKROOT/findings.ndjson"
(
    WP2SHELL_WP_CLI_RESOLVED="$STUB"
    WP2SHELL_RUN_ID=probetest
    WP2SHELL_FINDINGS_FILE="$FINDINGS"
    : > "$WP2SHELL_FINDINGS_FILE"
    detect_wp_for_site "$SITE" "$(id -un)" a.nl >/dev/null 2>&1
)

evidence=$(grep '"category":"wp-cli-unavailable"' "$FINDINGS" | head -1)
expect_contains "de bevinding draagt de reden als bewijs" \
    "Kon geen verbinding maken met de databaseserver" "$evidence"

printf '%s tests, %s mislukt\n' "$tests_run" "$tests_failed"
if [ "$tests_failed" -gt 0 ]; then
    exit 1
fi
exit 0
