#!/bin/bash
set -uo pipefail

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
. "$REPO_ROOT/lib/common.sh"
. "$REPO_ROOT/config/wp2shell.conf"
. "$REPO_ROOT/lib/version.sh"
. "$REPO_ROOT/lib/discovery.sh"
. "$REPO_ROOT/lib/detect_files.sh"
. "$REPO_ROOT/lib/detect_wp.sh"
. "$REPO_ROOT/lib/detect_logs.sh"
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

FIXTURE=$(mktemp -d -t wp2shell-fptest.XXXXXXXX)
trap 'rm -rf -- "$FIXTURE"' EXIT

WP2SHELL_RUN_ID="fptest"
WP2SHELL_FINDINGS_FILE="$FIXTURE/findings.ndjson"
WP2SHELL_AUDIT_LOG="$FIXTURE/audit.log"

count_actionable_high_confidence() {
    php -r '
        $n = 0;
        foreach (file($argv[1]) as $line) {
            $d = json_decode($line, true);
            if (!$d) { continue; }
            if ($d["confidence"] !== "high-confidence") { continue; }
            if ($d["severity"] === "info") { continue; }
            if ($d["file_path"] === "") { continue; }
            $n++;
        }
        echo $n;
    ' "$WP2SHELL_FINDINGS_FILE"
}

SITE="$FIXTURE/schoon"
mkdir -p "$SITE/wp-includes" "$SITE/wp-content/plugins/securityplugin/lib" \
    "$SITE/wp-content/plugins/securityplugin/waf" "$SITE/wp-content/plugins/cacheplugin"
{
    printf '<?php\n'
    printf '$wp_version = %s7.0.3%s;\n' "'" "'"
    printf '$wp_db_version = 60717;\n'
} > "$SITE/wp-includes/version.php"
printf '<?php\n' > "$SITE/wp-config.php"

printf '<?php\nregister_rest_route("myplugin/v1","/status",array("permission_callback" => "__return_true","callback"=>"cb"));\n' \
    > "$SITE/wp-content/plugins/securityplugin/lib/rest.php"
printf '<?php\n$config = base64_decode($stored_config);\nif ($mode) { exec($internal_command); }\n' \
    > "$SITE/wp-content/plugins/securityplugin/waf/engine.php"
printf '<?php $data = gzinflate(base64_decode($cached_payload));\n' \
    > "$SITE/wp-content/plugins/cacheplugin/cache.php"
printf 'auto_prepend_file = %s/home/klant/public_html/wp-content/plugins/securityplugin/waf-loader.php%s\n' "'" "'" \
    > "$SITE/.user.ini"

: > "$WP2SHELL_FINDINGS_FILE"
detect_files_for_site "$SITE" "$(id -un)" >/dev/null 2>&1

expect_equal "een schone site levert geen enkele automatisch te verwijderen bevinding" "0" \
    "$(count_actionable_high_confidence)"

expect_equal "de open REST-route alleen levert geen kwaadaardige pluginstructuur op" "0" \
    "$("${WP2SHELL_GREP:-grep}" -c 'malicious-plugin-structure' "$WP2SHELL_FINDINGS_FILE" || true)"

expect_equal "de .user.ini van een securityplugin gaat niet automatisch in quarantaine" "0" \
    "$("${WP2SHELL_GREP:-grep}" -c '"category":"user-ini-auto-prepend"' "$WP2SHELL_FINDINGS_FILE" || true)"

BAD="$FIXTURE/besmet"
mkdir -p "$BAD/wp-includes" "$BAD/wp-content/plugins/gg-abc123" "$BAD/wp-content/uploads"
{
    printf '<?php\n'
    printf '$wp_version = %s6.9.4%s;\n' "'" "'"
    printf '$wp_db_version = 60717;\n'
} > "$BAD/wp-includes/version.php"
printf '<?php\n' > "$BAD/wp-config.php"
printf '<?php\nregister_rest_route("evil/v1","/run",array("permission_callback"=>"__return_true","callback"=>function($r){passthru(base64_decode($r->get_param("c")));}));\n' \
    > "$BAD/wp-content/plugins/gg-abc123/shell.php"
printf 'auto_prepend_file=/home/klant/public_html/wp-content/uploads/loader.php\n' > "$BAD/.user.ini"

: > "$WP2SHELL_FINDINGS_FILE"
detect_files_for_site "$BAD" "$(id -un)" >/dev/null 2>&1

expect_equal "een webshellplugin in een bestand wordt wel bevestigd" "1" \
    "$("${WP2SHELL_GREP:-grep}" -c 'malicious-plugin-structure' "$WP2SHELL_FINDINGS_FILE" || true)"

expect_equal "een .user.ini die naar uploads wijst wordt wel bevestigd" "1" \
    "$("${WP2SHELL_GREP:-grep}" -c '"category":"user-ini-auto-prepend"' "$WP2SHELL_FINDINGS_FILE" || true)"

expect_equal "echte 207 wordt gelezen" "207" \
    "$(detect_logs_extract_status '1.2.3.4 - - [x] "POST /wp-json/batch/v1 HTTP/1.1" 207 512')"
expect_equal "een 404 in het requestveld verbergt de echte 207 niet" "207" \
    "$(detect_logs_extract_status '1.2.3.4 - - [x] "GET /wp-json/batch/v1?x=\" 404 y HTTP/1.1" 207 512')"
expect_equal "een vervalste 207 in het requestveld wordt niet geloofd" "404" \
    "$(detect_logs_extract_status '1.2.3.4 - - [x] "GET /x?a=\" 207 1 HTTP/1.1" 404 12')"
expect_equal "een streepje als bytecount breekt de statusparsing niet" "200" \
    "$(detect_logs_extract_status '1.2.3.4 - - [x] "GET / HTTP/1.1" 200 -')"

status_verdict_for() {
    local statuses=$1
    WP2SHELL_LOG_GROUP_STATUSES["proef"]="$statuses"
    local verdict=0
    detect_logs_group_has_success_status "proef" || verdict=$?
    printf '%s' "$verdict"
}

expect_equal "een 2xx geldt als geslaagd" "0" "$(status_verdict_for '200')"
expect_equal "alleen 4xx geldt als afgewezen" "1" "$(status_verdict_for '404 403')"
expect_equal "een 5xx geldt niet als afgewezen" "3" "$(status_verdict_for '500')"
expect_equal "een 5xx naast een 4xx blijft een serverfout" "3" "$(status_verdict_for '404 500')"
expect_equal "een 2xx wint van alles" "0" "$(status_verdict_for '404 500 200')"
expect_equal "zonder status is er geen oordeel" "2" "$(status_verdict_for '')"

expect_equal "een gewijzigd corebestand blokkeert het schoon-oordeel" "ja" \
    "$(category_blocks_clean_verdict "core-file-modified" && printf 'ja' || printf 'nee')"
expect_equal "een mislukte core-restore blokkeert het schoon-oordeel" "ja" \
    "$(category_blocks_clean_verdict "core-restore-failed" && printf 'ja' || printf 'nee')"
expect_equal "een beheerder uit het venster blokkeert het schoon-oordeel" "ja" \
    "$(category_blocks_clean_verdict "admin-created-in-exposure-window" && printf 'ja' || printf 'nee')"
expect_equal "een bestand in quarantaine blokkeert het schoon-oordeel" "ja" \
    "$(category_blocks_clean_verdict "php-in-writable-directory" && printf 'ja' || printf 'nee')"
expect_equal "een heuristisch codepatroon blokkeert het schoon-oordeel niet" "nee" \
    "$(category_blocks_clean_verdict "suspicious-code" && printf 'ja' || printf 'nee')"
expect_equal "een informatieve bevinding blokkeert het schoon-oordeel niet" "nee" \
    "$(category_blocks_clean_verdict "log-missing" && printf 'ja' || printf 'nee')"

expect_equal "een onbereikbare WP-CLI maakt de controle blind" "ja" \
    "$(category_indicates_blind_spot "wp-cli-unavailable" && printf 'ja' || printf 'nee')"
expect_equal "een mislukte checksumcontrole maakt de controle blind" "ja" \
    "$(category_indicates_blind_spot "core-checksums-unavailable" && printf 'ja' || printf 'nee')"
expect_equal "een onvolledige inventarisatie maakt de controle blind" "ja" \
    "$(category_indicates_blind_spot "scan-incomplete" && printf 'ja' || printf 'nee')"
expect_equal "een gewone bevinding maakt de controle niet blind" "nee" \
    "$(category_indicates_blind_spot "php-in-writable-directory" && printf 'ja' || printf 'nee')"

BLIND_FIXTURE="$FIXTURE/blind.ndjson"
{
    printf '{"category":"wp-cli-unavailable","confidence":"heuristic"}\n'
    printf '{"category":"log-missing","confidence":"high-confidence"}\n'
    printf '{"category":"wp-cli-unavailable","confidence":"heuristic"}\n'
} > "$BLIND_FIXTURE"
expect_equal "blinde vlekken worden ontdubbeld gemeld" "wp-cli-unavailable" \
    "$(collect_verification_blind_spots "$BLIND_FIXTURE")"

printf '{"category":"log-missing","confidence":"high-confidence"}\n' > "$BLIND_FIXTURE"
expect_equal "zonder blinde vlekken is de lijst leeg" "" \
    "$(collect_verification_blind_spots "$BLIND_FIXTURE")"

COMPLETE_FIXTURE="$FIXTURE/scope.ndjson"
printf '{"category":"wp-scan-scope","confidence":"high-confidence"}\n' > "$COMPLETE_FIXTURE"

expect_equal "volledig bewijs levert geen probleem op" "" \
    "$(verification_completeness_problems "$COMPLETE_FIXTURE" 0)"

expect_equal "een gestopte detector blokkeert het schoon-oordeel" "een van de controles is voortijdig gestopt" \
    "$(verification_completeness_problems "$COMPLETE_FIXTURE" 1)"

expect_equal "zonder afrondingsbewijs is de controle onvolledig" \
    "de WordPress-controles hebben geen afronding gemeld" \
    "$(printf '{"category":"log-missing","confidence":"info"}\n' > "$FIXTURE/noscope.ndjson"; verification_completeness_problems "$FIXTURE/noscope.ndjson" 0)"

SAVED_CORE=${WP2SHELL_SCAN_CORE_CHECKSUMS:-1}
WP2SHELL_SCAN_CORE_CHECKSUMS=0
expect_equal "uitgezette core-integriteitscontrole blokkeert het schoon-oordeel" \
    "de core-integriteitscontrole staat uit in de configuratie" \
    "$(verification_completeness_problems "$COMPLETE_FIXTURE" 0)"
WP2SHELL_SCAN_CORE_CHECKSUMS=$SAVED_CORE

SAVED_PLUGIN=${WP2SHELL_SCAN_PLUGIN_CHECKSUMS:-1}
WP2SHELL_SCAN_PLUGIN_CHECKSUMS=0
expect_equal "uitgezette plugin-integriteitscontrole blokkeert het schoon-oordeel" \
    "de plugin-integriteitscontrole staat uit in de configuratie" \
    "$(verification_completeness_problems "$COMPLETE_FIXTURE" 0)"
WP2SHELL_SCAN_PLUGIN_CHECKSUMS=$SAVED_PLUGIN

expect_equal "een onbekende tabelprefix blokkeert het schoon-oordeel" "ja" \
    "$(category_indicates_blind_spot "db-prefix-unknown" && printf 'ja' || printf 'nee')"
expect_equal "een mislukte autoload-query blokkeert het schoon-oordeel" "ja" \
    "$(category_indicates_blind_spot "db-autoload-query-failed" && printf 'ja' || printf 'nee')"

expect_equal "een onvolledige WordPress-controle blokkeert het schoon-oordeel" "ja" \
    "$(category_indicates_blind_spot "wp-checks-incomplete" && printf 'ja' || printf 'nee')"
expect_equal "onleesbare cron-uitvoer blokkeert het schoon-oordeel" "ja" \
    "$(category_indicates_blind_spot "cron-list-unparsable" && printf 'ja' || printf 'nee')"

WP_BADCRON="$FIXTURE/wp-badcron"
cat > "$WP_BADCRON" <<'STUBEOF'
#!/bin/bash
case " $* " in
    *" is-installed "*) exit 0 ;;
    *" db prefix "*) printf 'wp_\n'; exit 0 ;;
    *" db query "*) exit 0 ;;
    *" core version "*) printf '7.0.3\n'; exit 0 ;;
    *" verify-checksums "*) printf 'Success: WordPress installation verifies against checksums.\n'; exit 0 ;;
    *" user list "*) printf '[]\n'; exit 0 ;;
    *" option get active_plugins "*) printf '[]\n'; exit 0 ;;
    *" event list "*) printf 'geen-json-maar-wel-gevuld\n'; exit 0 ;;
    *) exit 0 ;;
esac
STUBEOF
chmod 0755 "$WP_BADCRON"

CRON_SITE="$FIXTURE/cronsite"
mkdir -p "$CRON_SITE/wp-includes" "$CRON_SITE/wp-admin" "$CRON_SITE/wp-content/plugins" "$CRON_SITE/wp-content/uploads"
{
    printf '<?php\n'
    printf '$wp_version = %s7.0.3%s;\n' "'" "'"
    printf '$wp_db_version = 60717;\n'
} > "$CRON_SITE/wp-includes/version.php"
printf '<?php\n' > "$CRON_SITE/wp-config.php"

CRON_RECHECK="$FIXTURE/cron-recheck.ndjson"
SAVED_CLI=${WP2SHELL_WP_CLI_RESOLVED:-}
SAVED_FINDINGS=$WP2SHELL_FINDINGS_FILE
WP2SHELL_WP_CLI_RESOLVED="$WP_BADCRON"
CRON_STATUS=0
rerun_detection_into "$CRON_SITE" "$(id -un)" "cron.nl" "$CRON_RECHECK" || CRON_STATUS=$?
WP2SHELL_WP_CLI_RESOLVED=$SAVED_CLI
WP2SHELL_FINDINGS_FILE=$SAVED_FINDINGS

expect_equal "onleesbare cron-uitvoer wordt wel gemeld" "1" \
    "$("${WP2SHELL_GREP:-grep}" -c 'cron-list-unparsable' "$CRON_RECHECK" || true)"
expect_equal "de onvolledige controle wordt apart vastgelegd" "1" \
    "$("${WP2SHELL_GREP:-grep}" -c 'wp-checks-incomplete' "$CRON_RECHECK" || true)"

CRON_PROBLEMS=$(verification_completeness_problems "$CRON_RECHECK" "$CRON_STATUS")
expect_equal "en die blokkeert het schoon-oordeel" "ja" \
    "$([ -n "$CRON_PROBLEMS" ] && printf 'ja' || printf 'nee')"

WP_BADPLUGINS="$FIXTURE/wp-badplugins"
cat > "$WP_BADPLUGINS" <<'STUBEOF'
#!/bin/bash
case " $* " in
    *" is-installed "*) exit 0 ;;
    *" db prefix "*) printf 'wp_\n'; exit 0 ;;
    *" db query "*) exit 0 ;;
    *" core version "*) printf '7.0.3\n'; exit 0 ;;
    *" verify-checksums "*) printf 'Success: WordPress installation verifies against checksums.\n'; exit 0 ;;
    *" user list "*) printf '[]\n'; exit 0 ;;
    *" event list "*) printf '[]\n'; exit 0 ;;
    *" option get active_plugins "*) printf 'geen-json-maar-wel-gevuld\n'; exit 0 ;;
    *) exit 0 ;;
esac
STUBEOF
chmod 0755 "$WP_BADPLUGINS"

PLUGIN_RECHECK="$FIXTURE/plugin-recheck.ndjson"
SAVED_CLI=${WP2SHELL_WP_CLI_RESOLVED:-}
SAVED_FINDINGS=$WP2SHELL_FINDINGS_FILE
WP2SHELL_WP_CLI_RESOLVED="$WP_BADPLUGINS"
PLUGIN_STATUS=0
rerun_detection_into "$CRON_SITE" "$(id -un)" "cron.nl" "$PLUGIN_RECHECK" || PLUGIN_STATUS=$?
WP2SHELL_WP_CLI_RESOLVED=$SAVED_CLI
WP2SHELL_FINDINGS_FILE=$SAVED_FINDINGS

expect_equal "onleesbare active_plugins wordt gemeld" "1" \
    "$("${WP2SHELL_GREP:-grep}" -c 'db-active-plugins-unparsable' "$PLUGIN_RECHECK" || true)"
expect_equal "de niet afgeronde controle wordt vastgelegd" "1" \
    "$("${WP2SHELL_GREP:-grep}" -c 'wp-checks-incomplete' "$PLUGIN_RECHECK" || true)"

PLUGIN_PROBLEMS=$(verification_completeness_problems "$PLUGIN_RECHECK" "$PLUGIN_STATUS")
expect_equal "en die blokkeert het schoon-oordeel" "ja" \
    "$([ -n "$PLUGIN_PROBLEMS" ] && printf 'ja' || printf 'nee')"

expect_equal "een controle die zich niet afmeldt telt als onafgerond" "1" \
    "$(WP2SHELL_DETECT_WP_FAILED_CHECKS=(); WP2SHELL_DETECT_WP_CHECK_COMPLETED=0; \
       detect_wp_run_child_check "proefcontrole" true >/dev/null 2>&1; \
       printf '%s' "${#WP2SHELL_DETECT_WP_FAILED_CHECKS[@]}")"
expect_equal "een controle die zich wel afmeldt telt als afgerond" "0" \
    "$(WP2SHELL_DETECT_WP_FAILED_CHECKS=(); WP2SHELL_DETECT_WP_CHECK_COMPLETED=0; \
       detect_wp_run_child_check "proefcontrole" detect_wp_mark_check_complete >/dev/null 2>&1; \
       printf '%s' "${#WP2SHELL_DETECT_WP_FAILED_CHECKS[@]}")"

GUARD_SITE="$FIXTURE/guardsite"
mkdir -p "$GUARD_SITE/wp-includes" "$GUARD_SITE/wp-content/uploads" "$GUARD_SITE/wp-content/cache"
{
    printf '<?php\n'
    printf '$wp_version = %s7.0.3%s;\n' "'" "'"
    printf '$wp_db_version = 60717;\n'
} > "$GUARD_SITE/wp-includes/version.php"
printf '<?php\n' > "$GUARD_SITE/wp-config.php"
printf '<?php\n' > "$GUARD_SITE/wp-content/uploads/index.php"
printf '<?php\n' > "$GUARD_SITE/wp-content/cache/index.php"
printf '<?php @eval($_POST["x"]);\n' > "$GUARD_SITE/wp-content/uploads/shell.php"
printf '<?php\n@eval($_POST["x"]);\n' > "$GUARD_SITE/wp-content/cache/index2.php"

SAVED_ALLOWLIST=("${WP2SHELL_ALLOWLIST_PATHS[@]}")
WP2SHELL_ALLOWLIST_PATHS=()
: > "$WP2SHELL_FINDINGS_FILE"
detect_files_for_site "$GUARD_SITE" "$(id -un)" >/dev/null 2>&1
WP2SHELL_ALLOWLIST_PATHS=("${SAVED_ALLOWLIST[@]}")

count_category_for() {
    php -r '
        $n = 0;
        foreach (file($argv[1]) as $line) {
            $d = json_decode($line, true);
            if (!$d) { continue; }
            if ($d["category"] !== $argv[2]) { continue; }
            if (basename($d["file_path"]) !== $argv[3]) { continue; }
            $n++;
        }
        echo $n;
    ' "$WP2SHELL_FINDINGS_FILE" "$1" "$2"
}

expect_equal "beide lege index.php bestanden worden met rust gelaten" "2" \
    "$(count_category_for directory-guard-present index.php)"
expect_equal "die index.php is geen op te ruimen bevinding" "0" \
    "$(count_category_for php-in-writable-directory index.php)"
expect_equal "een webshell in uploads blijft bevestigd" "1" \
    "$(count_category_for php-in-writable-directory shell.php)"
expect_equal "een index.php met eval erin blijft bevestigd" "1" \
    "$(count_category_for php-in-writable-directory index2.php)"

expect_equal "een lege index.php telt als onschuldige wachter" "ja" \
    "$(detect_files_is_harmless_directory_guard "$GUARD_SITE/wp-content/uploads/index.php" 6 && printf 'ja' || printf 'nee')"
expect_equal "een index.php met code telt niet als wachter" "nee" \
    "$(detect_files_is_harmless_directory_guard "$GUARD_SITE/wp-content/cache/index2.php" 30 && printf 'ja' || printf 'nee')"
expect_equal "onschuldige inhoud onder een andere naam telt niet als wachter" "nee" \
    "$(detect_files_is_harmless_directory_guard "$GUARD_SITE/wp-content/uploads/willekeurig.php" 6 && printf 'ja' || printf 'nee')"
expect_equal "een te groot bestand telt niet als wachter" "nee" \
    "$(detect_files_is_harmless_directory_guard "$GUARD_SITE/wp-content/uploads/index.php" 5000 && printf 'ja' || printf 'nee')"

BIG_SITE="$FIXTURE/bigsite"
mkdir -p "$BIG_SITE/wp-includes" "$BIG_SITE/wp-content/plugins"
{
    printf '<?php\n'
    printf '$wp_version = %s7.0.3%s;\n' "'" "'"
} > "$BIG_SITE/wp-includes/version.php"
printf '<?php\n' > "$BIG_SITE/wp-config.php"
printf '<?php\n' > "$BIG_SITE/wp-content/plugins/groot.php"
head -c 6000000 /dev/zero | tr '\0' 'A' >> "$BIG_SITE/wp-content/plugins/groot.php"

: > "$WP2SHELL_FINDINGS_FILE"
detect_files_for_site "$BIG_SITE" "$(id -un)" >/dev/null 2>&1
expect_equal "een te groot PHP-bestand wordt niet stil overgeslagen" "1" \
    "$("${WP2SHELL_GREP:-grep}" -c 'oversized-php-unscanned' "$WP2SHELL_FINDINGS_FILE" || true)"
expect_equal "en het blokkeert het schoon-oordeel niet" "nee" \
    "$(category_indicates_blind_spot "oversized-php-unscanned" && printf 'ja' || printf 'nee')"

printf '\n%s tests, %s mislukt\n' "$tests_run" "$tests_failed"
if [ "$tests_failed" -gt 0 ]; then
    exit 1
fi
