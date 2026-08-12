#!/bin/bash
set -euo pipefail

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
. "$REPO_ROOT/lib/common.sh"
. "$REPO_ROOT/config/wp2shell.conf"
. "$REPO_ROOT/lib/version.sh"

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

expect_wp2shell_status() {
    expect_equal "wp2shell status $1" "$2" "$(classify_wp2shell_status "$1")"
}

expect_security_status() {
    expect_equal "security status $1" "$2" "$(classify_current_security_status "$1")"
}

expect_branch() {
    expect_equal "branch $1" "$2" "$(wp_version_branch "$1")"
}

expect_normalized() {
    expect_equal "normalize $1" "$2" "$(wp_version_normalize "$1")"
}

expect_branch "6.9.5" "6.9"
expect_branch "6.9" "6.9"
expect_branch "7.0.2-RC1" "7.0"
expect_branch "6.9-alpha-59123" "6.9"
expect_branch "6.10.1" "6.10"

expect_normalized "6.9.5" "6.9.5"
expect_normalized "6.9-RC1" "6.9-RC1"
expect_normalized "6.9-beta2" "6.9-beta2"
expect_normalized "6.9-alpha-59123" "6.9-alpha-59123"
expect_normalized "6.8.6+wp1" "6.8.6"

expect_wp2shell_status "6.9.0" "$WP2SHELL_STATUS_RCE_VULNERABLE"
expect_wp2shell_status "6.9.4" "$WP2SHELL_STATUS_RCE_VULNERABLE"
expect_wp2shell_status "6.9.5" "$WP2SHELL_STATUS_PATCHED"
expect_wp2shell_status "6.9.6" "$WP2SHELL_STATUS_PATCHED"
expect_wp2shell_status "7.0.0" "$WP2SHELL_STATUS_RCE_VULNERABLE"
expect_wp2shell_status "7.0.1" "$WP2SHELL_STATUS_RCE_VULNERABLE"
expect_wp2shell_status "7.0.2" "$WP2SHELL_STATUS_PATCHED"
expect_wp2shell_status "7.0.3" "$WP2SHELL_STATUS_PATCHED"
expect_wp2shell_status "6.8.0" "$WP2SHELL_STATUS_SQLI_LATENT"
expect_wp2shell_status "6.8.5" "$WP2SHELL_STATUS_SQLI_LATENT"
expect_wp2shell_status "6.8.6" "$WP2SHELL_STATUS_PATCHED"
expect_wp2shell_status "6.8.10" "$WP2SHELL_STATUS_PATCHED"
expect_wp2shell_status "6.7.5" "$WP2SHELL_STATUS_NOT_AFFECTED"
expect_wp2shell_status "5.9.0" "$WP2SHELL_STATUS_NOT_AFFECTED"
expect_wp2shell_status "4.7.0" "$WP2SHELL_STATUS_NOT_AFFECTED"

expect_wp2shell_status "6.9-RC1" "$WP2SHELL_STATUS_RCE_VULNERABLE"
expect_wp2shell_status "6.9-beta2" "$WP2SHELL_STATUS_RCE_VULNERABLE"
expect_wp2shell_status "7.0.2-RC1" "$WP2SHELL_STATUS_RCE_VULNERABLE"
expect_wp2shell_status "7.1-beta2" "$WP2SHELL_STATUS_PATCHED"
expect_wp2shell_status "7.1" "$WP2SHELL_STATUS_PATCHED"
expect_wp2shell_status "7.2.0" "$WP2SHELL_STATUS_PATCHED"

expect_security_status "7.0.3" "$WP2SHELL_SECURITY_CURRENT"
expect_security_status "7.0.2" "$WP2SHELL_SECURITY_OUTDATED"
expect_security_status "6.9.6" "$WP2SHELL_SECURITY_CURRENT"
expect_security_status "6.9.5" "$WP2SHELL_SECURITY_OUTDATED"
expect_security_status "6.8.7" "$WP2SHELL_SECURITY_CURRENT"
expect_security_status "6.8.6" "$WP2SHELL_SECURITY_OUTDATED"
expect_security_status "6.7.6" "$WP2SHELL_SECURITY_CURRENT"
expect_security_status "4.6.0" "$WP2SHELL_SECURITY_UNSUPPORTED"

expect_equal "target voor 6.9.5" "6.9.6" "$(recommended_target_version "6.9.5")"
expect_equal "target voor 7.0.1" "7.0.3" "$(recommended_target_version "7.0.1")"
expect_equal "target voor 6.8.0" "6.8.7" "$(recommended_target_version "6.8.0")"

if version_at_least "6.8.10" "6.8.6"; then
    expect_equal "6.8.10 is nieuwer dan 6.8.6" "ja" "ja"
else
    expect_equal "6.8.10 is nieuwer dan 6.8.6" "ja" "nee"
fi

if version_at_least "6.9-RC1" "6.9"; then
    expect_equal "6.9-RC1 is ouder dan 6.9" "ja" "nee"
else
    expect_equal "6.9-RC1 is ouder dan 6.9" "ja" "ja"
fi

fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT
mkdir -p "$fixture/wp-includes"
{
    printf '<?php\n'
    printf '$wp_version = %s6.9.4%s;\n' "'" "'"
    printf '$wp_db_version = 60717;\n'
} > "$fixture/wp-includes/version.php"

expect_equal "versie van schijf" "6.9.4" "$(wp_version_from_disk "$fixture")"
expect_equal "db-versie van schijf" "60717" "$(wp_db_version_from_disk "$fixture")"

evaluate_site_version "$fixture"
expect_equal "evaluate versie" "6.9.4" "$WP2SHELL_SITE_VERSION"
expect_equal "evaluate branch" "6.9" "$WP2SHELL_SITE_BRANCH"
expect_equal "evaluate wp2shell status" "$WP2SHELL_STATUS_RCE_VULNERABLE" "$WP2SHELL_SITE_WP2SHELL_STATUS"
expect_equal "evaluate security status" "$WP2SHELL_SECURITY_OUTDATED" "$WP2SHELL_SITE_SECURITY_STATUS"
expect_equal "evaluate doelversie" "6.9.6" "$WP2SHELL_SITE_TARGET_VERSION"

printf '\n%s tests, %s mislukt\n' "$tests_run" "$tests_failed"
if [ "$tests_failed" -gt 0 ]; then
    exit 1
fi
