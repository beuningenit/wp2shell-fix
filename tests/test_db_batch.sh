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

expect_true() {
    local label=$1 status=$2
    tests_run=$((tests_run + 1))
    if [ "$status" = "0" ]; then
        printf 'ok   %s\n' "$label"
    else
        printf 'FAIL %s\n' "$label" >&2
        tests_failed=$((tests_failed + 1))
    fi
}

WORKROOT=$(mktemp -d)
trap 'rm -rf -- "$WORKROOT"' EXIT

SITE="$WORKROOT/home/klant/domains/a.nl/public_html"
mkdir -p "$SITE/wp-includes" "$SITE/wp-admin" "$SITE/wp-content/plugins" "$SITE/wp-content/themes"
printf '<?php\n$table_prefix = "wp_";\n' > "$SITE/wp-config.php"
printf '<?php\n' > "$SITE/wp-load.php"
printf '<?php $wp_version = "7.0.3";\n' > "$SITE/wp-includes/version.php"

write_stub() {
    local target=$1 mode=$2
    cat > "$target" <<'STUB'
#!/bin/bash
printf 'x\n' >> "${WP2SHELL_WP_CALL_LOG:-/dev/null}"
args=("$@")
sql=''
for i in "${!args[@]}"; do
    if [ "${args[$i]}" = "query" ]; then sql="${args[$((i+1))]}"; fi
done

emit_one() {
    local q=$1
    if [ "$q" = "SELECT 1" ]; then printf '1\n'; return; fi
    case $q in
        "SELECT '"*"'")
            q=${q#SELECT \'}
            printf '%s\n' "${q%\'}"
            return
            ;;
    esac
    case $q in
        *'MAX(ID), 0) FROM'*posts*)
            printf '412\n' ;;
        *'post_type IN'*)
            printf '407\tcustomize_changeset\tauto-draft\t0\t2026-07-20 04:11:02\t2026-07-20 04:11:02\ts:14:"evilpayload";\n'
            if [ "$WP2SHELL_STUB_MODE" = "inject" ]; then
                printf '0123456789abcdef0123456789abcdef:orphan-admins\n999\n'
            fi
            ;;
        *'COUNT(*), COALESCE(MIN(ID)'*)
            printf '3\t1\t9\n' ;;
        *'COUNT(DISTINCT m.user_id)'*)
            printf '2\n' ;;
        *'DISTINCT m.user_id'*)
            printf '77\n' ;;
        *"option_name IN ('siteurl'"*)
            printf 'siteurl\thttps://a.nl\nhome\thttps://a.nl\n' ;;
        *oembed*)
            printf 'oembed_abc123\ts:4:"evil";\n' ;;
        *'autoload, LENGTH'*LIKE*)
            printf 'kaboom\tyes\t900\t1\t0\t0\tbase64_decode(\n' ;;
        *'autoload, LENGTH'*)
            printf 'kaboom\tyes\t900\n' ;;
    esac
}

case " $* " in
    *" db query "*)
        if [ "$WP2SHELL_STUB_MODE" = "faal" ]; then
            case $sql in
                *"
"*)
                    printf 'ERROR 1064 (42000): You have an error in your SQL syntax\n' >&2
                    exit 1
                    ;;
            esac
        fi
        while IFS= read -r stmt; do
            stmt="${stmt%;}"
            [ -n "$stmt" ] || continue
            if [ "$WP2SHELL_STUB_MODE" = "half" ]; then
                case $stmt in
                    *oembed*) exit 0 ;;
                esac
            fi
            emit_one "$stmt"
        done < <(printf '%s\n' "$sql")
        exit 0
        ;;
    *" is-installed "*) exit 0 ;;
    *" db prefix "*) printf 'wp_\n'; exit 0 ;;
    *" core version "*) printf '7.0.3\n'; exit 0 ;;
    *" verify-checksums "*) printf 'Success: WordPress installation verifies against checksums.\n'; exit 0 ;;
    *" user list "*|*" event list "*) printf '[]\n'; exit 0 ;;
    *" option get active_plugins "*) printf '[]\n'; exit 0 ;;
    *) exit 0 ;;
esac
STUB
    chmod 0755 -- "$target"
    printf '%s' "$mode" > "$target.mode"
}

STUB_BIN="$WORKROOT/wp-stub"
write_stub "$STUB_BIN" normaal

run_detection() {
    local mode=$1 batch=$2 tag=$3
    (
        WP2SHELL_STUB_MODE=$mode
        export WP2SHELL_STUB_MODE
        WP2SHELL_DETECT_WP_DB_BATCH=$batch
        export WP2SHELL_DETECT_WP_DB_BATCH
        WP2SHELL_WP_CALL_LOG="$WORKROOT/calls.$tag"
        export WP2SHELL_WP_CALL_LOG
        : > "$WP2SHELL_WP_CALL_LOG"
        WP2SHELL_WP_CLI_RESOLVED="$STUB_BIN"
        WP2SHELL_RUN_ID=testrun
        WP2SHELL_FINDINGS_FILE="$WORKROOT/findings.$tag.ndjson"
        : > "$WP2SHELL_FINDINGS_FILE"
        detect_wp_for_site "$SITE" "$(id -un)" a.nl >/dev/null 2>&1
    )
    return 0
}

normalize_findings() {
    sed 's/"timestamp":"[^"]*"//' "$1" | LC_ALL=C sort
}

compare_modes() {
    local mode=$1 label=$2
    run_detection "$mode" 0 "${mode}0"
    run_detection "$mode" 1 "${mode}1"
    local plain="$WORKROOT/findings.${mode}0.ndjson"
    local batched="$WORKROOT/findings.${mode}1.ndjson"
    local status=0
    diff -q <(normalize_findings "$plain") <(normalize_findings "$batched") >/dev/null || status=1
    expect_true "$label geeft dezelfde bevindingen als losse queries" "$status"
    local count
    count=$(wc -l < "$plain")
    tests_run=$((tests_run + 1))
    if [ "$count" -gt 0 ]; then
        printf 'ok   %s levert bevindingen op\n' "$label"
    else
        printf 'FAIL %s levert geen enkele bevinding op, de test zegt dan niets\n' "$label" >&2
        tests_failed=$((tests_failed + 1))
    fi
}

detect_optional_commands >/dev/null 2>&1
resolve_external_tools >/dev/null 2>&1

compare_modes normaal "gebundelde databasequery"
compare_modes faal "batch die volledig mislukt"
compare_modes half "batch die halverwege afbreekt"
compare_modes inject "aanvaller die een sectiemarkering injecteert"

calls_plain=$(wc -l < "$WORKROOT/calls.normaal0")
calls_batched=$(wc -l < "$WORKROOT/calls.normaal1")
tests_run=$((tests_run + 1))
if [ "$calls_batched" -lt "$calls_plain" ]; then
    printf 'ok   bundelen scheelt WP-CLI-aanroepen (%s tegenover %s)\n' "$calls_batched" "$calls_plain"
else
    printf 'FAIL bundelen scheelt geen aanroepen (%s tegenover %s)\n' "$calls_batched" "$calls_plain" >&2
    tests_failed=$((tests_failed + 1))
fi

nonce_a=$(detect_wp_batch_nonce)
nonce_b=$(detect_wp_batch_nonce)
expect_equal "sectiemarkering heeft de volle lengte" "32" "${#nonce_a}"
tests_run=$((tests_run + 1))
if [ "$nonce_a" != "$nonce_b" ]; then
    printf 'ok   sectiemarkering verschilt per keer\n'
else
    printf 'FAIL sectiemarkering is voorspelbaar\n' >&2
    tests_failed=$((tests_failed + 1))
fi

WP2SHELL_DETECT_WP_BATCH_READY=' site-urls '
expect_true "bekend label wordt uit de bundel gelezen" "$(detect_wp_batch_has_label site-urls && printf 0 || printf 1)"
expect_equal "onbekend label valt terug op een losse query" "1" "$(detect_wp_batch_has_label oembed-options && printf 0 || printf 1)"
WP2SHELL_DETECT_WP_BATCH_READY=''

for label in autoload-options autoload-size site-urls max-post-id bridge-posts oembed-options user-range orphan-usermeta orphan-admins; do
    sql=$(detect_wp_batch_sql_for_label "$label" "wp_") || sql=''
    tests_run=$((tests_run + 1))
    if [ -n "$sql" ]; then
        printf 'ok   SQL voor %s wordt centraal opgebouwd\n' "$label"
    else
        printf 'FAIL SQL voor %s ontbreekt in de bundel\n' "$label" >&2
        tests_failed=$((tests_failed + 1))
    fi
done

printf '%s tests, %s mislukt\n' "$tests_run" "$tests_failed"
if [ "$tests_failed" -gt 0 ]; then
    exit 1
fi
exit 0
