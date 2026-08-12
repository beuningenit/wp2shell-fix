#!/bin/bash
set -euo pipefail

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
. "$REPO_ROOT/lib/common.sh"
. "$REPO_ROOT/config/wp2shell.conf"
. "$REPO_ROOT/lib/version.sh"
. "$REPO_ROOT/lib/discovery.sh"

detect_optional_commands

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

FIXTURE=$(mktemp -d -t wp2shell-fixture.XXXXXXXX)
trap 'rm -rf -- "$FIXTURE"' EXIT

make_wordpress() {
    local root=$1 version=$2 db_version=$3
    mkdir -p "$root/wp-includes" "$root/wp-content/plugins" "$root/wp-content/uploads" "$root/wp-admin"
    {
        printf '<?php\n'
        printf '$wp_version = %s%s%s;\n' "'" "$version" "'"
        printf '$wp_db_version = %s;\n' "$db_version"
    } > "$root/wp-includes/version.php"
    printf '<?php\n' > "$root/wp-config.php"
    printf '<?php\n' > "$root/index.php"
}

WP2SHELL_HOME_BASE="$FIXTURE/home"
WP2SHELL_DOCROOT_GLOBS=(
    "$FIXTURE/home/*/domains/*/public_html"
    "$FIXTURE/home/*/domains/*/private_html"
)

make_wordpress "$FIXTURE/home/alice/domains/example.com/public_html" "6.9.4" "60717"
make_wordpress "$FIXTURE/home/alice/domains/example.com/public_html/shop" "7.0.1" "60717"
make_wordpress "$FIXTURE/home/bob/domains/test.nl/public_html" "6.8.6" "58975"
make_wordpress "$FIXTURE/home/carol/domains/oud.nl/public_html" "6.7.5" "58975"

ln -s "$FIXTURE/home/bob/domains/test.nl/public_html" "$FIXTURE/home/bob/domains/test.nl/private_html"

mkdir -p "$FIXTURE/home/dave/domains/raar.nl/public_html"
make_wordpress "$FIXTURE/home/dave/domains/raar.nl/public_html/map met spaties" "6.9.2" "60717"
make_wordpress "$FIXTURE/home/dave/domains/raar.nl/public_html/map'met\"quotes" "6.9.3" "60717"

mkdir -p "$FIXTURE/home/alice/domains/example.com/public_html/node_modules/pakket"
make_wordpress "$FIXTURE/home/alice/domains/example.com/public_html/node_modules/pakket" "6.9.0" "60717"

SITES_FILE="$FIXTURE/sites.ndjson"
discover_sites "$SITES_FILE" 2>/dev/null

found_count=$(wc -l < "$SITES_FILE")
expect_equal "aantal gevonden installaties" "6" "$found_count"

expect_equal "node_modules wordt overgeslagen" "0" \
    "$(grep -c 'node_modules' "$SITES_FILE" || true)"

expect_equal "private_html symlink levert geen duplicaat" "1" \
    "$(grep -c '"domain":"test.nl"' "$SITES_FILE" || true)"

expect_equal "pad met spaties gevonden" "1" \
    "$(grep -c 'map met spaties' "$SITES_FILE" || true)"

expect_equal "pad met quotes gevonden" "1" \
    "$(grep -c "map'met" "$SITES_FILE" || true)"

quotes_line=$(grep "map'met" "$SITES_FILE")
expect_equal "quote correct geescaped in JSON" "1" \
    "$(printf '%s' "$quotes_line" | grep -c 'map.met\\"quotes' || true)"

expect_equal "pad met quotes komt heel terug uit JSON" \
    "$FIXTURE/home/dave/domains/raar.nl/public_html/map'met\"quotes" \
    "$(site_record_field "$quotes_line" site_path)"

spaces_line=$(grep 'map met spaties' "$SITES_FILE")
expect_equal "pad met spaties komt heel terug uit JSON" \
    "$FIXTURE/home/dave/domains/raar.nl/public_html/map met spaties" \
    "$(site_record_field "$spaces_line" site_path)"

expect_equal "escapes in json_extract_field" 'regel1
regel2	tab' \
    "$(json_extract_field '{"a":"regel1\nregel2\ttab","b":1}' a)"

expect_equal "backslash in json_extract_field" 'pad\met\slashes' \
    "$(json_extract_field '{"a":"pad\\met\\slashes"}' a)"

if [ "${WP2SHELL_HAS_JQ:-0}" = "1" ]; then
    expect_equal "JSON is geldig" "6" "$(jq -s 'length' < "$SITES_FILE")"
else
    expect_equal "JSON validatie via php" "6" \
        "$(php -r '$n=0; foreach(file($argv[1]) as $l){ if(trim($l)===""){continue;} if(json_decode($l)===null){ exit(1);} $n++; } echo $n;' "$SITES_FILE")"
fi

shop_line=$(grep '"relative_path":"/shop"' "$SITES_FILE")
expect_equal "subinstallatie gemarkeerd" "true" \
    "$(site_record_field "$shop_line" is_subinstall)"
expect_equal "subinstallatie domein" "example.com" \
    "$(site_record_field "$shop_line" domain)"
expect_equal "subinstallatie url" "https://example.com/shop/" \
    "$(site_record_field "$shop_line" url)"

root_line=$(grep '"relative_path":"/"' "$SITES_FILE" | grep 'example.com' | head -1)
expect_equal "hoofdinstallatie niet als subinstall" "false" \
    "$(site_record_field "$root_line" is_subinstall)"
expect_equal "hoofdinstallatie url" "https://example.com/" \
    "$(site_record_field "$root_line" url)"
expect_equal "directadmin gebruiker uit pad" "alice" \
    "$(site_record_field "$root_line" directadmin_user)"

RESTRICT_FILE="$FIXTURE/sites-bob.ndjson"
discover_sites "$RESTRICT_FILE" "" "bob" 2>/dev/null
expect_equal "beperken tot gebruiker bob" "1" "$(wc -l < "$RESTRICT_FILE")"

SINGLE_FILE="$FIXTURE/sites-single.ndjson"
discover_sites "$SINGLE_FILE" "$FIXTURE/home/carol/domains/oud.nl/public_html" 2>/dev/null
expect_equal "beperken tot een site" "1" "$(wc -l < "$SINGLE_FILE")"

version_of_carol=$(wp_version_from_disk "$FIXTURE/home/carol/domains/oud.nl/public_html")
expect_equal "versie carol" "6.7.5" "$version_of_carol"
expect_equal "carol niet geraakt door wp2shell" "$WP2SHELL_STATUS_NOT_AFFECTED" \
    "$(classify_wp2shell_status "$version_of_carol")"
expect_equal "carol mist wel de actuele securityrelease" "$WP2SHELL_SECURITY_OUTDATED" \
    "$(classify_current_security_status "$version_of_carol")"

printf '\n%s tests, %s mislukt\n' "$tests_run" "$tests_failed"
if [ "$tests_failed" -gt 0 ]; then
    exit 1
fi
