#!/bin/bash
set -uo pipefail

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
. "$REPO_ROOT/lib/common.sh"
. "$REPO_ROOT/config/wp2shell.conf"
. "$REPO_ROOT/lib/version.sh"
. "$REPO_ROOT/lib/discovery.sh"
. "$REPO_ROOT/lib/quarantine.sh"
. "$REPO_ROOT/lib/harden.sh"

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

FIXTURE=$(mktemp -d -t wp2shell-htest.XXXXXXXX)
trap 'rm -rf -- "$FIXTURE"' EXIT

WP2SHELL_RUN_ID="testrun"
WP2SHELL_FINDINGS_FILE="$FIXTURE/findings.ndjson"
WP2SHELL_AUDIT_LOG="$FIXTURE/audit.log"
: > "$WP2SHELL_FINDINGS_FILE"

SITE="$FIXTURE/site"
mkdir -p "$SITE/wp-content/uploads" "$SITE/wp-content/cache"

{
    printf '# BEGIN WordPress\n'
    printf 'RewriteEngine On\n'
    printf 'RewriteRule . /index.php [L]\n'
    printf '# END WordPress\n'
} > "$SITE/.htaccess"

ORIGINAL_SUM=$(sha1sum < "$SITE/.htaccess")

harden_htaccess_for_site "$SITE" 1 >/dev/null 2>&1

BEGIN_LINE=$("${WP2SHELL_GREP:-grep}" -n '^# BEGIN wp2shell-hardening$' "$SITE/.htaccess" | cut -d: -f1)
WP_LINE=$("${WP2SHELL_GREP:-grep}" -n '^# BEGIN WordPress$' "$SITE/.htaccess" | cut -d: -f1)
expect_equal "hardeningblok staat voor het WordPress-blok" "ja" \
    "$([ "$BEGIN_LINE" -lt "$WP_LINE" ] && printf 'ja' || printf 'nee')"

expect_equal "het WordPress-blok is intact gebleven" "1" \
    "$("${WP2SHELL_GREP:-grep}" -c '^RewriteRule \. /index\.php \[L\]$' "$SITE/.htaccess")"

expect_equal "de probe-regel staat erin" "1" \
    "$("${WP2SHELL_GREP:-grep}" -c 'wp2shell-hardening-active' "$SITE/.htaccess")"

expect_equal "php in uploads en cache wordt geblokkeerd" "1" \
    "$("${WP2SHELL_GREP:-grep}" -c 'wp-content/(?:uploads|cache)' "$SITE/.htaccess")"

expect_equal "wp-config.php wordt beschermd" "1" \
    "$("${WP2SHELL_GREP:-grep}" -c 'wp-config\\.php' "$SITE/.htaccess")"

expect_equal "er wordt geen Files-directive gebruikt" "0" \
    "$("${WP2SHELL_GREP:-grep}" -ci '<Files' "$SITE/.htaccess" || true)"

expect_equal "er wordt geen php_value gebruikt" "0" \
    "$("${WP2SHELL_GREP:-grep}" -ci 'php_value' "$SITE/.htaccess" || true)"

expect_equal "uploads heeft een eigen .htaccess" "ja" \
    "$([ -f "$SITE/wp-content/uploads/.htaccess" ] && printf 'ja' || printf 'nee')"
expect_equal "cache heeft een eigen .htaccess" "ja" \
    "$([ -f "$SITE/wp-content/cache/.htaccess" ] && printf 'ja' || printf 'nee')"

expect_equal "blok wordt als actueel herkend" "ja" \
    "$(htaccess_block_is_current "$SITE/.htaccess" && printf 'ja' || printf 'nee')"

AFTER_FIRST=$(sha1sum < "$SITE/.htaccess")
harden_htaccess_for_site "$SITE" 1 >/dev/null 2>&1
AFTER_SECOND=$(sha1sum < "$SITE/.htaccess")
expect_equal "tweede run wijzigt niets, idempotent" "$AFTER_FIRST" "$AFTER_SECOND"

expect_equal "het blok staat er maar een keer in" "1" \
    "$("${WP2SHELL_GREP:-grep}" -c '^# BEGIN wp2shell-hardening$' "$SITE/.htaccess")"

printf 'RewriteRule ^oud$ - [F]\n' >> "$SITE/.htaccess"
sed -i 's|^RewriteRule ^/?wp2shell-hardening-active\$ - \[F,L,NC\]$|RewriteRule ^/?verouderd$ - [F,L,NC]|' "$SITE/.htaccess"
expect_equal "verouderd blok wordt niet als actueel gezien" "nee" \
    "$(htaccess_block_is_current "$SITE/.htaccess" && printf 'ja' || printf 'nee')"

harden_htaccess_for_site "$SITE" 1 >/dev/null 2>&1
expect_equal "verouderd blok is vervangen, niet gedupliceerd" "1" \
    "$("${WP2SHELL_GREP:-grep}" -c '^# BEGIN wp2shell-hardening$' "$SITE/.htaccess")"
expect_equal "de probe-regel is hersteld" "1" \
    "$("${WP2SHELL_GREP:-grep}" -c 'wp2shell-hardening-active' "$SITE/.htaccess")"
expect_equal "eigen regels van de klant blijven staan" "1" \
    "$("${WP2SHELL_GREP:-grep}" -c '^RewriteRule \^oud\$ - \[F\]$' "$SITE/.htaccess")"

SITE2="$FIXTURE/site2"
mkdir -p "$SITE2"
harden_htaccess_for_site "$SITE2" 1 >/dev/null 2>&1
expect_equal "site zonder bestaande .htaccess krijgt er een" "ja" \
    "$([ -f "$SITE2/.htaccess" ] && printf 'ja' || printf 'nee')"

SITE3="$FIXTURE/site3"
mkdir -p "$SITE3"
: > "$WP2SHELL_FINDINGS_FILE"
harden_htaccess_for_site "$SITE3" 0 >/dev/null 2>&1
expect_equal "zonder --apply wordt er niets geschreven" "nee" \
    "$([ -f "$SITE3/.htaccess" ] && printf 'ja' || printf 'nee')"
expect_equal "zonder --apply wordt het wel gerapporteerd" "1" \
    "$("${WP2SHELL_GREP:-grep}" -c 'hardening-missing' "$WP2SHELL_FINDINGS_FILE" || true)"

expect_equal "de payload bevat geen em dash of en dash" "0" \
    "$(docroot_htaccess_payload | "${WP2SHELL_GREP:-grep}" -c -e $'\u2014' -e $'\u2013' || true)"

printf '\n%s tests, %s mislukt\n' "$tests_run" "$tests_failed"
if [ "$tests_failed" -gt 0 ]; then
    exit 1
fi
