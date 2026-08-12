#!/bin/bash
set -uo pipefail

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
. "$REPO_ROOT/lib/common.sh"
. "$REPO_ROOT/config/wp2shell.conf"
. "$REPO_ROOT/lib/version.sh"
. "$REPO_ROOT/lib/discovery.sh"
. "$REPO_ROOT/lib/backup.sh"
. "$REPO_ROOT/lib/quarantine.sh"

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

expect_success() {
    local label=$1
    shift
    tests_run=$((tests_run + 1))
    if "$@" >/dev/null 2>&1; then
        printf 'ok   %s\n' "$label"
    else
        printf 'FAIL %s: commando gaf een fout\n' "$label" >&2
        tests_failed=$((tests_failed + 1))
    fi
}

expect_failure() {
    local label=$1
    shift
    tests_run=$((tests_run + 1))
    if "$@" >/dev/null 2>&1; then
        printf 'FAIL %s: commando slaagde terwijl weigering werd verwacht\n' "$label" >&2
        tests_failed=$((tests_failed + 1))
    else
        printf 'ok   %s\n' "$label"
    fi
}

FIXTURE=$(mktemp -d -t wp2shell-qtest.XXXXXXXX)
trap 'rm -rf -- "$FIXTURE"' EXIT

WP2SHELL_RUN_ID="testrun"
WP2SHELL_QUARANTINE_DIR="$FIXTURE/quarantine"
WP2SHELL_BACKUP_DIR="$FIXTURE/backups"
WP2SHELL_HOME_BASE="$FIXTURE/home"
WP2SHELL_FINDINGS_FILE="$FIXTURE/findings.ndjson"
WP2SHELL_AUDIT_LOG="$FIXTURE/audit.log"
: > "$WP2SHELL_FINDINGS_FILE"

SITE="$FIXTURE/home/alice/domains/voorbeeld.nl/public_html"
mkdir -p "$SITE/wp-content/uploads/2026/08" "$SITE/wp-includes" "$SITE/buiten"
printf '<?php eval($_POST[1]);\n' > "$SITE/wp-content/uploads/2026/08/shell.php"
printf '<?php normale inhoud\n' > "$SITE/wp-content/uploads/2026/08/gewoon.txt"
printf 'geheim buiten de site\n' > "$FIXTURE/buiten-de-site.txt"
ln -s "$FIXTURE/buiten-de-site.txt" "$SITE/wp-content/uploads/ontsnapping.php"

expect_success "quarantaine van een echt bestand" \
    quarantine_file "$SITE" "$SITE/wp-content/uploads/2026/08/shell.php" "webshell in uploads" "$CONFIDENCE_HIGH" alice

expect_equal "het bestand is weg van de oorspronkelijke plek" "nee" \
    "$([ -e "$SITE/wp-content/uploads/2026/08/shell.php" ] && printf 'ja' || printf 'nee')"

STORED="$FIXTURE/quarantine/testrun/$(site_identifier "$SITE")/files/wp-content/uploads/2026/08/shell.php"
expect_equal "het bestand staat in quarantaine" "ja" \
    "$([ -f "$STORED" ] && printf 'ja' || printf 'nee')"

expect_equal "relatief pad blijft behouden" "ja" \
    "$(printf '%s' "$STORED" | "${WP2SHELL_GREP:-grep}" -q 'wp-content/uploads/2026/08/shell.php' && printf 'ja' || printf 'nee')"

MANIFEST=$(quarantine_manifest_path "$SITE")
expect_equal "manifest heeft een regel" "1" "$(wc -l < "$MANIFEST")"

MANIFEST_LINE=$(head -1 "$MANIFEST")
expect_equal "manifest bevat het originele pad" "$SITE/wp-content/uploads/2026/08/shell.php" \
    "$(json_extract_field "$MANIFEST_LINE" original_path)"
expect_equal "manifest bevat een sha1" "40" \
    "$(printf '%s' "$(json_extract_field "$MANIFEST_LINE" sha1)" | wc -c)"
expect_equal "manifest bevat een sha256" "64" \
    "$(printf '%s' "$(json_extract_field "$MANIFEST_LINE" sha256)" | wc -c)"
expect_equal "manifest bevat de reden" "webshell in uploads" \
    "$(json_extract_field "$MANIFEST_LINE" reason)"

expect_failure "symlink wordt nooit verplaatst" \
    quarantine_file "$SITE" "$SITE/wp-content/uploads/ontsnapping.php" "verdacht" "$CONFIDENCE_HIGH" alice
expect_equal "het doelwit van de symlink staat er nog" "ja" \
    "$([ -f "$FIXTURE/buiten-de-site.txt" ] && printf 'ja' || printf 'nee')"
expect_equal "de symlink zelf staat er nog" "ja" \
    "$([ -L "$SITE/wp-content/uploads/ontsnapping.php" ] && printf 'ja' || printf 'nee')"

expect_failure "bestand buiten de site wordt geweigerd" \
    quarantine_file "$SITE" "$FIXTURE/buiten-de-site.txt" "verdacht" "$CONFIDENCE_HIGH" alice

expect_failure "heuristische bevinding gaat nooit automatisch in quarantaine" \
    quarantine_file "$SITE" "$SITE/wp-content/uploads/2026/08/gewoon.txt" "heuristiek" "$CONFIDENCE_HEURISTIC" alice
expect_equal "het heuristische bestand staat er nog" "ja" \
    "$([ -f "$SITE/wp-content/uploads/2026/08/gewoon.txt" ] && printf 'ja' || printf 'nee')"

expect_success "terugzetten vanuit het manifest" restore_from_manifest "$MANIFEST"
expect_equal "het bestand staat weer op zijn plek" "ja" \
    "$([ -f "$SITE/wp-content/uploads/2026/08/shell.php" ] && printf 'ja' || printf 'nee')"
expect_equal "de inhoud is ongewijzigd teruggezet" '<?php eval($_POST[1]);' \
    "$(cat "$SITE/wp-content/uploads/2026/08/shell.php")"

expect_failure "backup in de docroot wordt geweigerd" \
    backup_location_is_safe "$SITE/backups" "$SITE"
expect_failure "backup in een gebruikershome wordt geweigerd" \
    backup_location_is_safe "$FIXTURE/home/alice/backups" "$SITE"
expect_success "backup buiten de docroot is toegestaan" \
    backup_location_is_safe "$FIXTURE/backups/x" "$SITE"

expect_success "archiveren van de docroot" \
    backup_files_archive "$SITE" "$FIXTURE/test.tar.gz"
expect_success "het archief is verifieerbaar" verify_files_archive "$FIXTURE/test.tar.gz"

ARCHIVE_VERBOSE=$("${WP2SHELL_TAR:-tar}" --list --verbose --file="$FIXTURE/test.tar.gz" 2>/dev/null)
expect_equal "de symlink is als symlink opgeslagen, niet als inhoud" "1" \
    "$(printf '%s\n' "$ARCHIVE_VERBOSE" | "${WP2SHELL_GREP:-grep}" -c '^l.*ontsnapping\.php ->' || true)"

mkdir -p "$FIXTURE/uitgepakt"
"${WP2SHELL_TAR:-tar}" --extract --file="$FIXTURE/test.tar.gz" --directory="$FIXTURE/uitgepakt" 2>/dev/null
EXTRACTED_LINK="$FIXTURE/uitgepakt/public_html/wp-content/uploads/ontsnapping.php"
expect_equal "na uitpakken is het nog steeds een symlink" "ja" \
    "$([ -L "$EXTRACTED_LINK" ] && printf 'ja' || printf 'nee')"
expect_equal "de geheime inhoud van buiten de site zit niet in het archief" "0" \
    "$("${WP2SHELL_GREP:-grep}" -rl 'geheim buiten de site' "$FIXTURE/uitgepakt" 2>/dev/null | wc -l)"

expect_failure "een leeg archief wordt afgekeurd" verify_files_archive "$FIXTURE/leeg.tar.gz"
printf 'geen sql\n' > "$FIXTURE/slecht.sql"
expect_failure "een dump zonder CREATE TABLE wordt afgekeurd" verify_database_dump "$FIXTURE/slecht.sql"
printf 'CREATE TABLE wp_posts (id int);\n' > "$FIXTURE/goed.sql"
expect_success "een geldige dump wordt geaccepteerd" verify_database_dump "$FIXTURE/goed.sql"

printf '\n%s tests, %s mislukt\n' "$tests_run" "$tests_failed"
if [ "$tests_failed" -gt 0 ]; then
    exit 1
fi
