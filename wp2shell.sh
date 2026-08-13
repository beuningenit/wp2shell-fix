#!/bin/bash
set -uo pipefail

WP2SHELL_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
WP2SHELL_TOOLKIT_VERSION="1.0.0"

. "$WP2SHELL_ROOT/lib/common.sh"
. "$WP2SHELL_ROOT/lib/version.sh"
. "$WP2SHELL_ROOT/lib/discovery.sh"
. "$WP2SHELL_ROOT/lib/reference.sh"
. "$WP2SHELL_ROOT/lib/detect_integrity.sh"
. "$WP2SHELL_ROOT/lib/detect_regex.sh"
. "$WP2SHELL_ROOT/lib/crosssite.sh"
. "$WP2SHELL_ROOT/lib/detect_host.sh"
. "$WP2SHELL_ROOT/lib/detect_files.sh"
. "$WP2SHELL_ROOT/lib/detect_wp.sh"
. "$WP2SHELL_ROOT/lib/detect_logs.sh"
. "$WP2SHELL_ROOT/lib/backup.sh"
. "$WP2SHELL_ROOT/lib/quarantine.sh"
. "$WP2SHELL_ROOT/lib/clean.sh"
. "$WP2SHELL_ROOT/lib/harden.sh"
. "$WP2SHELL_ROOT/lib/report.sh"

OPT_SUBCOMMAND=""
OPT_APPLY=0
OPT_SITE=""
OPT_USER=""
OPT_EMAIL=""
OPT_PARALLEL=""
OPT_QUARANTINE_DIR=""
OPT_BACKUP_DIR=""
OPT_REMOVE_ADMINS=0
OPT_MAINTENANCE=0
OPT_CONFIG=""
OPT_NO_MAIL=0
OPT_RUN_ID=""
OPT_FILTER=""

usage() {
    cat <<'USAGE'
wp2shell.sh, detectie- en opschoontoolkit voor de wp2shell-kwetsbaarheden

Gebruik:
  wp2shell.sh <subcommando> [opties]

Subcommando's:
  scan       Read-only inventarisatie en detectie. Wijzigt niets. Standaardgedrag.
  clean      Opschonen van besmette installaties. Doet niets zonder --apply.
  harden     Preventie toepassen. Wijzigende stappen alleen met --apply.
  report     Laatste resultaten opnieuw renderen en optioneel mailen.
  restore    Zet bestanden uit quarantaine terug. Doet niets zonder --apply.

Opties:
  --apply                 Schakel wijzigende acties in. Zonder deze vlag wordt niets gewijzigd.
  --site <pad>            Beperk tot een enkele WordPress-installatie.
  --user <gebruiker>      Beperk tot een DirectAdmin-gebruiker.
  --email <adres>         Stuur het rapport naar dit adres.
  --no-mail               Verstuur geen e-mail, schrijf alleen bestanden.
  --parallel <n>          Aantal gelijktijdige sites. Standaard 1.
  --quarantine-dir <pad>  Locatie voor bestanden in quarantaine.
  --backup-dir <pad>      Locatie voor backups.
  --remove-admins         Sta het verwijderen van verdachte adminaccounts toe. Aparte opt-in.
  --maintenance           Zet de site in onderhoudsmodus tijdens het opschonen.
  --config <pad>          Alternatief configuratiebestand.
  --run-id <id>           Hergebruik een bestaande run. Verplicht bij report en restore.
  --filter <tekst>        Bij restore, zet alleen paden terug die deze tekst bevatten.
  --verbose               Toon debugmeldingen.
  --help                  Toon deze hulptekst.

Exitcodes:
  0   geen bevindingen
  1   verkeerd gebruik
  2   interne fout
  3   een andere run is al bezig
  10  alleen informatieve bevindingen
  20  lage ernst
  30  middelhoge ernst, handmatige review nodig
  40  hoge ernst, kwetsbare versie of vermoedelijke blootstelling
  50  kritiek, bevestigde compromittering

Voorbeelden:
  wp2shell.sh scan
  wp2shell.sh scan --user klantnaam
  wp2shell.sh clean --site /home/klant/domains/voorbeeld.nl/public_html --apply
  wp2shell.sh harden --apply
  wp2shell.sh restore --run-id 20260813-090000-1234
  wp2shell.sh restore --run-id 20260813-090000-1234 --apply
  wp2shell.sh restore --run-id 20260813-090000-1234 --filter wp-content/uploads --apply
USAGE
}

parse_arguments() {
    if [ "$#" -eq 0 ]; then
        usage
        exit "$EXIT_USAGE"
    fi
    while [ "$#" -gt 0 ]; do
        case $1 in
            scan|clean|harden|report|restore)
                if [ -n "$OPT_SUBCOMMAND" ]; then
                    log_error "Meerdere subcommando's opgegeven: $OPT_SUBCOMMAND en $1"
                    exit "$EXIT_USAGE"
                fi
                OPT_SUBCOMMAND=$1
                ;;
            --apply) OPT_APPLY=1 ;;
            --remove-admins) OPT_REMOVE_ADMINS=1 ;;
            --maintenance) OPT_MAINTENANCE=1 ;;
            --no-mail) OPT_NO_MAIL=1 ;;
            --verbose) WP2SHELL_VERBOSE=1 ;;
            --help|-h) usage; exit "$EXIT_OK" ;;
            --site)
                shift || true
                OPT_SITE=${1:-}
                if [ -z "$OPT_SITE" ]; then
                    log_error "--site vereist een pad"
                    exit "$EXIT_USAGE"
                fi
                ;;
            --user)
                shift || true
                OPT_USER=${1:-}
                if [ -z "$OPT_USER" ]; then
                    log_error "--user vereist een gebruikersnaam"
                    exit "$EXIT_USAGE"
                fi
                ;;
            --email)
                shift || true
                OPT_EMAIL=${1:-}
                if [ -z "$OPT_EMAIL" ]; then
                    log_error "--email vereist een adres"
                    exit "$EXIT_USAGE"
                fi
                ;;
            --parallel)
                shift || true
                OPT_PARALLEL=${1:-}
                case $OPT_PARALLEL in
                    ''|*[!0-9]*)
                        log_error "--parallel vereist een geheel getal"
                        exit "$EXIT_USAGE"
                        ;;
                esac
                ;;
            --quarantine-dir)
                shift || true
                OPT_QUARANTINE_DIR=${1:-}
                ;;
            --backup-dir)
                shift || true
                OPT_BACKUP_DIR=${1:-}
                ;;
            --config)
                shift || true
                OPT_CONFIG=${1:-}
                ;;
            --run-id)
                shift || true
                OPT_RUN_ID=${1:-}
                ;;
            --filter)
                shift || true
                OPT_FILTER=${1:-}
                ;;
            *)
                log_error "Onbekende optie: $1"
                usage
                exit "$EXIT_USAGE"
                ;;
        esac
        shift || true
    done
    if [ -z "$OPT_SUBCOMMAND" ]; then
        OPT_SUBCOMMAND=scan
    fi
}

validate_arguments() {
    if [ "$OPT_SUBCOMMAND" = "restore" ] && [ -z "$OPT_RUN_ID" ]; then
        log_error "restore vereist --run-id van de run waarin de bestanden in quarantaine zijn gezet"
        exit "$EXIT_USAGE"
    fi
    if [ "$OPT_SUBCOMMAND" = "restore" ] && [ "$OPT_APPLY" != "1" ]; then
        log_warn "restore zet bestanden terug in de live site, dat vereist --apply"
    fi
    if [ -n "$OPT_FILTER" ] && [ "$OPT_SUBCOMMAND" != "restore" ]; then
        log_error "--filter hoort bij restore"
        exit "$EXIT_USAGE"
    fi
    if [ "$OPT_SUBCOMMAND" = "scan" ] && [ "$OPT_APPLY" = "1" ]; then
        log_error "scan is altijd read-only, gebruik clean of harden met --apply"
        exit "$EXIT_USAGE"
    fi
    if [ "$OPT_REMOVE_ADMINS" = "1" ] && [ "$OPT_SUBCOMMAND" != "clean" ]; then
        log_error "--remove-admins hoort bij clean"
        exit "$EXIT_USAGE"
    fi
    if [ "$OPT_REMOVE_ADMINS" = "1" ] && [ "$OPT_APPLY" != "1" ]; then
        log_warn "--remove-admins zonder --apply, verdachte accounts worden alleen gerapporteerd"
    fi
    if [ -n "$OPT_SITE" ] && [ -n "$OPT_USER" ]; then
        log_error "Gebruik --site of --user, niet allebei"
        exit "$EXIT_USAGE"
    fi
    return 0
}

apply_option_overrides() {
    if [ -n "$OPT_EMAIL" ]; then
        WP2SHELL_REPORT_EMAIL="$OPT_EMAIL"
    fi
    if [ -n "$OPT_PARALLEL" ]; then
        WP2SHELL_PARALLEL_JOBS="$OPT_PARALLEL"
    fi
    if [ -n "$OPT_QUARANTINE_DIR" ]; then
        WP2SHELL_QUARANTINE_DIR="$OPT_QUARANTINE_DIR"
    fi
    if [ -n "$OPT_BACKUP_DIR" ]; then
        WP2SHELL_BACKUP_DIR="$OPT_BACKUP_DIR"
    fi
    return 0
}

resolve_report_directory() {
    local preferred=${WP2SHELL_REPORT_DIR:-}
    if [ -n "$preferred" ] && mkdir -p -- "$preferred" 2>/dev/null && [ -w "$preferred" ]; then
        printf '%s' "$preferred"
        return 0
    fi
    local fallback="$WP2SHELL_ROOT/reports"
    mkdir -p -- "$fallback" 2>/dev/null || true
    printf '%s' "$fallback"
    return 0
}

setup_run_environment() {
    WP2SHELL_RUN_ID="${OPT_RUN_ID:-$(timestamp_compact)-$$}"
    local report_base
    report_base=$(resolve_report_directory)
    WP2SHELL_REPORT_DIR="$report_base"
    WP2SHELL_RUN_DIR="$report_base/$WP2SHELL_RUN_ID"
    if ! mkdir -p -- "$WP2SHELL_RUN_DIR"; then
        die "$EXIT_INTERNAL" "Kan rapportmap niet aanmaken: $WP2SHELL_RUN_DIR"
    fi
    chmod 0750 -- "$WP2SHELL_RUN_DIR" 2>/dev/null || true
    WP2SHELL_RUN_LOG="$WP2SHELL_RUN_DIR/run.log"
    WP2SHELL_AUDIT_LOG="$WP2SHELL_RUN_DIR/audit.log"
    WP2SHELL_FINDINGS_FILE="$WP2SHELL_RUN_DIR/findings.ndjson"
    WP2SHELL_SITES_FILE="$WP2SHELL_RUN_DIR/sites.ndjson"
    WP2SHELL_REPORT_JSON="$WP2SHELL_RUN_DIR/report.json"
    WP2SHELL_REPORT_TEXT="$WP2SHELL_RUN_DIR/samenvatting.txt"
    case $OPT_SUBCOMMAND in
        report|restore)
            if [ ! -e "$WP2SHELL_FINDINGS_FILE" ]; then
                : > "$WP2SHELL_FINDINGS_FILE"
            fi
            if [ ! -e "$WP2SHELL_SITES_FILE" ]; then
                : > "$WP2SHELL_SITES_FILE"
            fi
            ;;
        *)
            : > "$WP2SHELL_FINDINGS_FILE"
            : > "$WP2SHELL_SITES_FILE"
            ;;
    esac
    WP2SHELL_STARTED_AT=$(timestamp_iso)
    return 0
}

check_dependencies() {
    if ! require_command php sha1sum sha256sum curl date stat base64; then
        die "$EXIT_INTERNAL" "Niet alle vereiste commando's zijn aanwezig"
    fi
    detect_optional_commands
    if ! resolve_external_tools; then
        die "$EXIT_INTERNAL" "Kan de vereiste externe tools niet vaststellen"
    fi
    if [ "${WP2SHELL_HAS_JQ:-0}" != "1" ]; then
        log_debug "jq is niet aanwezig, er wordt teruggevallen op de ingebouwde JSON-verwerking"
    fi
    if ! ensure_wp_cli; then
        log_warn "WP-CLI is niet beschikbaar, de controles op database en core-integriteit worden overgeslagen"
        WP2SHELL_WP_CLI_MISSING=1
    else
        WP2SHELL_WP_CLI_MISSING=0
        log_debug "WP-CLI in gebruik: ${WP2SHELL_WP_CLI_RESOLVED:-}"
    fi
    return 0
}

warn_about_privileges() {
    local user
    user=$(current_user_name)
    if [ "$user" != "root" ]; then
        if [ "$OPT_SUBCOMMAND" = "clean" ] || [ "$OPT_SUBCOMMAND" = "harden" ]; then
            log_warn "Deze run draait als $user en niet als root, acties op andere gebruikers zullen falen"
        else
            log_warn "Deze run draait als $user en niet als root, niet alle installaties zijn zichtbaar"
        fi
    fi
    return 0
}

classify_discovered_sites() {
    local sites_file=$1
    local enriched="$sites_file.enriched"
    : > "$enriched"
    local record site_path
    while IFS= read -r record || [ -n "$record" ]; do
        if [ -z "$record" ]; then
            continue
        fi
        site_path=$(site_record_field "$record" site_path) || site_path=''
        if [ -z "$site_path" ]; then
            printf '%s\n' "$record" >> "$enriched"
            continue
        fi
        if ! evaluate_site_version "$site_path"; then
            log_warn "Kan versie niet bepalen voor $site_path"
            printf '%s\n' "${record%\}}, \"version\":null, \"version_readable\":false}" >> "$enriched"
            record_finding \
                "site=$site_path" \
                "severity=$SEVERITY_MEDIUM" \
                "confidence=$CONFIDENCE_HEURISTIC" \
                "category=version-unreadable" \
                "title=Versie kon niet gelezen worden" \
                "detail=wp-includes/version.php is aanwezig maar bevat geen leesbare versie. Dit kan wijzen op een beschadigde of gemanipuleerde installatie." \
                "remediation=Controleer deze installatie handmatig."
            continue
        fi
        append_version_fields "$record" >> "$enriched"
        report_version_findings "$site_path"
    done < "$sites_file"
    mv -f -- "$enriched" "$sites_file"
    return 0
}

append_version_fields() {
    local record=$1
    printf '%s,' "${record%\}}"
    printf '"version":%s,' "$(json_string "$WP2SHELL_SITE_VERSION")"
    printf '"branch":%s,' "$(json_string "$WP2SHELL_SITE_BRANCH")"
    printf '"db_version":%s,' "$(json_string "$WP2SHELL_SITE_DB_VERSION")"
    printf '"wp2shell_status":%s,' "$(json_string "$WP2SHELL_SITE_WP2SHELL_STATUS")"
    printf '"security_status":%s,' "$(json_string "$WP2SHELL_SITE_SECURITY_STATUS")"
    printf '"target_version":%s,' "$(json_string "$WP2SHELL_SITE_TARGET_VERSION")"
    printf '"version_readable":true'
    printf '}\n'
    return 0
}

report_version_findings() {
    local site_path=$1
    local status="$WP2SHELL_SITE_WP2SHELL_STATUS"
    local severity
    severity=$(severity_for_wp2shell_status "$status")
    case $status in
        "$WP2SHELL_STATUS_RCE_VULNERABLE")
            record_finding \
                "site=$site_path" \
                "severity=$severity" \
                "confidence=$CONFIDENCE_HIGH" \
                "category=vulnerable-version" \
                "title=Kwetsbaar voor de volledige wp2shell RCE-keten" \
                "detail=Deze installatie draait WordPress $WP2SHELL_SITE_VERSION en is kwetsbaar voor CVE-2026-63030 in combinatie met CVE-2026-60137. Dit is pre-auth remote code execution." \
                "remediation=Werk direct bij naar minimaal $WP2SHELL_SITE_TARGET_VERSION en behandel deze site als mogelijk gecompromitteerd."
            ;;
        "$WP2SHELL_STATUS_SQLI_LATENT")
            record_finding \
                "site=$site_path" \
                "severity=$severity" \
                "confidence=$CONFIDENCE_HIGH" \
                "category=vulnerable-version" \
                "title=Kwetsbaar voor de SQL-injectie uit CVE-2026-60137" \
                "detail=Deze installatie draait WordPress $WP2SHELL_SITE_VERSION. De RCE-keten werkt hier niet, want de batch-route-verwarring bestaat pas vanaf 6.9. De SQL-injectie is alleen misbruikbaar wanneer een plugin of thema onvertrouwde invoer aan author__not_in doorgeeft." \
                "remediation=Werk bij naar minimaal $WP2SHELL_SITE_TARGET_VERSION."
            ;;
        "$WP2SHELL_STATUS_UNKNOWN")
            record_finding \
                "site=$site_path" \
                "severity=$severity" \
                "confidence=$CONFIDENCE_HEURISTIC" \
                "category=unknown-version" \
                "title=Onbekende WordPress-versie" \
                "detail=De versie $WP2SHELL_SITE_VERSION valt buiten de bekende versietabellen." \
                "remediation=Controleer handmatig en werk de versietabellen in de configuratie bij."
            ;;
    esac
    if [ "$WP2SHELL_SITE_SECURITY_STATUS" = "$WP2SHELL_SECURITY_OUTDATED" ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_HIGH" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=outdated-security-release" \
            "title=Mist de securityrelease van 6 augustus 2026" \
            "detail=Deze installatie draait WordPress $WP2SHELL_SITE_VERSION. Los van wp2shell is er op 6 augustus 2026 een securityrelease uitgekomen met twaalf oplossingen, waaronder CVE-2026-64638, een pre-auth XSS met een pad naar uitvoering van PHP-code." \
            "remediation=Werk bij naar $WP2SHELL_SITE_TARGET_VERSION."
    fi
    if [ "$WP2SHELL_SITE_SECURITY_STATUS" = "$WP2SHELL_SECURITY_UNSUPPORTED" ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_HIGH" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=unsupported-version" \
            "title=Draait een WordPress-versie zonder security-ondersteuning" \
            "detail=Versie $WP2SHELL_SITE_VERSION krijgt geen beveiligingsupdates meer." \
            "remediation=Plan een migratie naar een ondersteunde versie."
    fi
    if [ -n "$WP2SHELL_SITE_BRANCH" ] && [ -n "$WP2SHELL_SITE_DB_VERSION" ]; then
        local expected=${WP2SHELL_DB_VERSION_REFERENCE[$WP2SHELL_SITE_BRANCH]:-}
        if [ -n "$expected" ] && [ "$expected" != "$WP2SHELL_SITE_DB_VERSION" ]; then
            record_finding \
                "site=$site_path" \
                "severity=$SEVERITY_MEDIUM" \
                "confidence=$CONFIDENCE_HEURISTIC" \
                "category=version-mismatch" \
                "title=Databaseversie past niet bij de WordPress-versie" \
                "detail=version.php meldt versie $WP2SHELL_SITE_VERSION met databaseversie $WP2SHELL_SITE_DB_VERSION, terwijl voor branch $WP2SHELL_SITE_BRANCH databaseversie $expected wordt verwacht. Op een gecompromitteerde host is version.php eenvoudig te vervalsen." \
                "remediation=Controleer de core-integriteit met wp core verify-checksums."
        fi
    fi
    return 0
}

run_detection_sequential() {
    local line site_path owner_user domain rc
    while IFS= read -r line || [ -n "$line" ]; do
        if [ -z "$line" ]; then
            continue
        fi
        site_path=$(site_record_field "$line" site_path) || site_path=''
        owner_user=$(site_record_field "$line" effective_user) || owner_user=''
        domain=$(site_record_field "$line" domain) || domain=''
        if [ -z "$site_path" ]; then
            continue
        fi
        ( detect_all_for_site "$site_path" "$owner_user" "$domain" )
        rc=$?
        if [ "$rc" -ne 0 ]; then
            log_warn "Detectie op $site_path eindigde met exitcode $rc"
        fi
    done < "$WP2SHELL_SITES_FILE"
    return 0
}

run_detection_parallel() {
    local jobs=$1
    local worker_dir index=0 line site_path owner_user domain
    worker_dir=$(make_temp_dir wp2shell-detect)
    register_temp_cleanup "$worker_dir"
    while IFS= read -r line || [ -n "$line" ]; do
        if [ -z "$line" ]; then
            continue
        fi
        site_path=$(site_record_field "$line" site_path) || site_path=''
        owner_user=$(site_record_field "$line" effective_user) || owner_user=''
        domain=$(site_record_field "$line" domain) || domain=''
        if [ -z "$site_path" ]; then
            continue
        fi
        index=$((index + 1))
        (
            WP2SHELL_FINDINGS_FILE="$worker_dir/$index.ndjson"
            : > "$WP2SHELL_FINDINGS_FILE"
            detect_all_for_site "$site_path" "$owner_user" "$domain"
        ) &
        while [ "$(jobs -rp | wc -l)" -ge "$jobs" ]; do
            wait -n 2>/dev/null || true
        done
    done < "$WP2SHELL_SITES_FILE"
    wait
    local worker_file
    for worker_file in "$worker_dir"/*.ndjson; do
        if [ -f "$worker_file" ] && [ -s "$worker_file" ]; then
            cat -- "$worker_file" >> "$WP2SHELL_FINDINGS_FILE"
        fi
    done
    log_info "$index sites parallel gescand met maximaal $jobs tegelijk"
    return 0
}

feed_crosssite_over_all_sites() {
    local line site_path
    while IFS= read -r line || [ -n "$line" ]; do
        if [ -z "$line" ]; then
            continue
        fi
        site_path=$(site_record_field "$line" site_path) || site_path=''
        if [ -n "$site_path" ]; then
            feed_crosssite_from_findings "$site_path" || true
        fi
    done < "$WP2SHELL_SITES_FILE"
    return 0
}

run_detection_over_sites() {
    if ! require_detection_modules; then
        return 1
    fi
    if declare -F reference_begin_run >/dev/null 2>&1; then
        reference_begin_run || true
        reference_purge_expired || true
    fi
    local jobs=${WP2SHELL_PARALLEL_JOBS:-1}
    case $jobs in
        ''|*[!0-9]*) jobs=1 ;;
    esac
    if [ "$jobs" -le 1 ]; then
        run_detection_sequential
    else
        run_detection_parallel "$jobs"
    fi
    feed_crosssite_over_all_sites
    if declare -F detect_logs_server_wide >/dev/null 2>&1; then
        detect_logs_server_wide || true
    fi
    detect_host_persistence || true
    crosssite_report || true
    if declare -F reference_fetch_cap_reached >/dev/null 2>&1 && reference_fetch_cap_reached; then
        record_finding \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=reference-fetch-cap-reached" \
            "title=De limiet op het ophalen van referentiepakketten is bereikt" \
            "detail=Er zijn deze run meer pakketten nodig dan de ingestelde limiet toestaat, dus niet elke plugin of elk thema is tegen de officiele release vergeleken. Die installaties zijn op dat punt niet gecontroleerd." \
            "remediation=Verhoog WP2SHELL_REFERENCE_MAX_FETCHES_PER_RUN in de configuratie of draai de scan opnieuw, dan wordt de cache verder aangevuld."
    fi
    return 0
}

require_detection_modules() {
    local missing=() name
    for name in detect_files_for_site detect_wp_for_site detect_logs_for_site \
        detect_integrity_for_site detect_host_persistence crosssite_report \
        crosssite_record_candidate detect_regex_scan_file; do
        if ! declare -F "$name" >/dev/null 2>&1; then
            missing+=("$name")
        fi
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        log_error "Detectiemodules ontbreken: ${missing[*]}"
        record_finding \
            "severity=$SEVERITY_CRITICAL" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=detection-unavailable" \
            "title=Er is helemaal geen detectie uitgevoerd" \
            "detail=De volgende detectiefuncties zijn niet geladen: ${missing[*]}. Er is dus alleen op versienummer gekeken. Dit rapport zegt niets over besmetting en mag onder geen beding als schoon gelezen worden." \
            "remediation=Controleer of de installatie compleet is en draai de scan opnieuw."
        return 1
    fi
    return 0
}

WP2SHELL_CROSSSITE_EXCLUDED_CATEGORIES=(
    "directory-guard-present"
    "php-in-writable-directory-allowlisted"
    "integrity-unverified"
    "integrity-package-dir-missing"
    "integrity-coverage-partial"
    "integrity-summary"
    "core-file-outdated"
    "oversized-php-unscanned"
    "mu-plugin-present"
)

category_is_crosssite_candidate() {
    local candidate=$1 entry
    if [ -z "$candidate" ]; then
        return 1
    fi
    for entry in "${WP2SHELL_CROSSSITE_EXCLUDED_CATEGORIES[@]}"; do
        if [ "$entry" = "$candidate" ]; then
            return 1
        fi
    done
    return 0
}

feed_crosssite_from_findings() {
    local site_path=$1
    if [ ! -s "${WP2SHELL_FINDINGS_FILE:-}" ]; then
        return 0
    fi
    local snapshot line record_site confidence category rank file_path digest fed=0
    snapshot=$(mktemp -t wp2shell-xsite.XXXXXXXX) || return 0
    register_temp_cleanup "$snapshot"
    cp -- "$WP2SHELL_FINDINGS_FILE" "$snapshot"
    while IFS= read -r line || [ -n "$line" ]; do
        if [ -z "$line" ]; then
            continue
        fi
        record_site=$(json_extract_field "$line" site_path) || record_site=''
        if [ "$record_site" != "$site_path" ]; then
            continue
        fi
        confidence=$(json_extract_field "$line" confidence) || confidence=''
        if [ "$confidence" != "$CONFIDENCE_HIGH" ] && [ "$confidence" != "$CONFIDENCE_HEURISTIC" ]; then
            continue
        fi
        category=$(json_extract_field "$line" category) || category=''
        if ! category_is_crosssite_candidate "$category"; then
            continue
        fi
        rank=$(json_extract_field "$line" severity_rank) || rank=0
        case $rank in
            ''|*[!0-9]*) rank=0 ;;
        esac
        if [ "$rank" -lt 30 ]; then
            continue
        fi
        file_path=$(json_extract_field "$line" file_path) || file_path=''
        if [ -z "$file_path" ] || [ ! -f "$file_path" ] || [ -L "$file_path" ]; then
            continue
        fi
        digest=$(file_sha256 "$file_path") || digest=''
        if [ -z "$digest" ]; then
            continue
        fi
        crosssite_record_candidate "$site_path" "$file_path" "$digest" "$confidence" || true
        fed=$((fed + 1))
    done < "$snapshot"
    log_debug "$fed verdachte bestanden aangeboden aan de kruisvergelijking voor $site_path"
    return 0
}

detect_all_for_site() {
    local site_path=$1 owner_user=$2 domain=$3
    detect_files_for_site "$site_path" "$owner_user" || true
    detect_integrity_for_site "$site_path" "$owner_user" || true
    detect_wp_for_site "$site_path" "$owner_user" "$domain" || true
    detect_logs_for_site "$site_path" "$domain" || true
    return 0
}

command_scan() {
    log_info "Start read-only scan"
    if ! discover_sites "$WP2SHELL_SITES_FILE" "$OPT_SITE" "$OPT_USER"; then
        die "$EXIT_INTERNAL" "Discovery is mislukt"
    fi
    classify_discovered_sites "$WP2SHELL_SITES_FILE"
    run_detection_over_sites
    return 0
}

record_site_failure() {
    local site_path=$1 rc=$2
    log_error "Verwerking van $site_path is mislukt met exitcode $rc, de overige sites gaan door"
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_MEDIUM" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=site-processing-failed" \
        "title=Verwerking van deze site is mislukt" \
        "detail=De verwerking eindigde met exitcode $rc. Andere sites zijn wel verwerkt. Deze site is niet volledig behandeld en mag niet als schoon gelden." \
        "remediation=Bekijk het runlogboek voor de oorzaak en behandel deze site opnieuw."
    return 0
}

merge_worker_findings() {
    local worker_dir=$1
    local worker_file
    for worker_file in "$worker_dir"/*.ndjson; do
        if [ -f "$worker_file" ] && [ -s "$worker_file" ]; then
            cat -- "$worker_file" >> "$WP2SHELL_FINDINGS_FILE"
        fi
    done
    return 0
}

iterate_sites_sequential() {
    local handler=$1
    local total=0 failed=0 line site_path owner_user target_version domain rc
    while IFS= read -r line || [ -n "$line" ]; do
        if [ -z "$line" ]; then
            continue
        fi
        site_path=$(site_record_field "$line" site_path) || site_path=''
        owner_user=$(site_record_field "$line" effective_user) || owner_user=''
        target_version=$(site_record_field "$line" target_version) || target_version=''
        domain=$(site_record_field "$line" domain) || domain=''
        if [ -z "$site_path" ] || [ -z "$owner_user" ]; then
            log_warn "Siterecord zonder pad of eigenaar wordt overgeslagen"
            continue
        fi
        total=$((total + 1))
        ( "$handler" "$site_path" "$owner_user" "$target_version" "$domain" )
        rc=$?
        if [ "$rc" -ne 0 ]; then
            failed=$((failed + 1))
            record_site_failure "$site_path" "$rc"
        fi
    done < "$WP2SHELL_SITES_FILE"
    log_info "$total sites verwerkt, $failed mislukt"
    return 0
}

iterate_sites_parallel() {
    local handler=$1 jobs=$2
    local worker_dir total=0 index=0 line site_path owner_user target_version domain
    worker_dir=$(make_temp_dir wp2shell-workers)
    register_temp_cleanup "$worker_dir"
    local -a pending_paths=()
    while IFS= read -r line || [ -n "$line" ]; do
        if [ -z "$line" ]; then
            continue
        fi
        site_path=$(site_record_field "$line" site_path) || site_path=''
        owner_user=$(site_record_field "$line" effective_user) || owner_user=''
        target_version=$(site_record_field "$line" target_version) || target_version=''
        domain=$(site_record_field "$line" domain) || domain=''
        if [ -z "$site_path" ] || [ -z "$owner_user" ]; then
            log_warn "Siterecord zonder pad of eigenaar wordt overgeslagen"
            continue
        fi
        total=$((total + 1))
        index=$((index + 1))
        pending_paths+=("$site_path")
        (
            WP2SHELL_FINDINGS_FILE="$worker_dir/$index.ndjson"
            : > "$WP2SHELL_FINDINGS_FILE"
            "$handler" "$site_path" "$owner_user" "$target_version" "$domain"
            printf '%s' "$?" > "$worker_dir/$index.status"
        ) &
        while [ "$(jobs -rp | wc -l)" -ge "$jobs" ]; do
            wait -n 2>/dev/null || true
        done
    done < "$WP2SHELL_SITES_FILE"
    wait
    merge_worker_findings "$worker_dir"
    local failed=0 position=0 status_file status
    for position in "${!pending_paths[@]}"; do
        status_file="$worker_dir/$((position + 1)).status"
        status=1
        if [ -f "$status_file" ]; then
            status=$(cat -- "$status_file" 2>/dev/null) || status=1
        fi
        case $status in
            ''|*[!0-9]*) status=1 ;;
        esac
        if [ "$status" -ne 0 ]; then
            failed=$((failed + 1))
            record_site_failure "${pending_paths[$position]}" "$status"
        fi
    done
    log_info "$total sites verwerkt, $failed mislukt"
    return 0
}

iterate_sites() {
    local handler=$1
    local jobs=${WP2SHELL_PARALLEL_JOBS:-1}
    case $jobs in
        ''|*[!0-9]*) jobs=1 ;;
    esac
    if [ "$jobs" -le 1 ]; then
        iterate_sites_sequential "$handler"
        return $?
    fi
    log_info "Parallelle verwerking met maximaal $jobs sites tegelijk"
    iterate_sites_parallel "$handler" "$jobs"
    return $?
}

handle_clean_site() {
    local site_path=$1 owner_user=$2 target_version=$3 domain=${4:-}
    clean_site "$site_path" "$owner_user" "$OPT_APPLY" "$OPT_REMOVE_ADMINS" "$OPT_MAINTENANCE" "$target_version" "$domain"
}

handle_harden_site() {
    local site_path=$1 owner_user=$2 target_version=$3 domain=${4:-}
    local exposed=0
    if [ -n "$target_version" ]; then
        exposed=1
    fi
    update_core_for_site "$site_path" "$owner_user" "$OPT_APPLY" "$target_version" || true
    harden_htaccess_for_site "$site_path" "$OPT_APPLY" || true
    harden_wp_configuration "$site_path" "$owner_user" "$OPT_APPLY" || true
    rotate_salts_for_site "$site_path" "$owner_user" "$OPT_APPLY" "$exposed" || true
    normalize_permissions_for_site "$site_path" "$owner_user" "$OPT_APPLY" || true
    remove_stopgap_muplugin "$site_path" "$OPT_APPLY" 1 || true
    return 0
}

verify_hardening_after_restart() {
    local line site_path url
    while IFS= read -r line || [ -n "$line" ]; do
        if [ -z "$line" ]; then
            continue
        fi
        site_path=$(site_record_field "$line" site_path) || site_path=''
        url=$(site_record_field "$line" url) || url=''
        if [ -n "$site_path" ] && [ -n "$url" ]; then
            verify_hardening_enforced "$site_path" "$url" || true
        fi
    done < "$WP2SHELL_SITES_FILE"
    return 0
}

command_clean() {
    log_info "Start opschoning"
    if ! discover_sites "$WP2SHELL_SITES_FILE" "$OPT_SITE" "$OPT_USER"; then
        die "$EXIT_INTERNAL" "Discovery is mislukt"
    fi
    classify_discovered_sites "$WP2SHELL_SITES_FILE"
    run_detection_over_sites
    iterate_sites handle_clean_site
    return 0
}

command_harden() {
    log_info "Start hardening"
    if ! discover_sites "$WP2SHELL_SITES_FILE" "$OPT_SITE" "$OPT_USER"; then
        die "$EXIT_INTERNAL" "Discovery is mislukt"
    fi
    classify_discovered_sites "$WP2SHELL_SITES_FILE"
    iterate_sites handle_harden_site
    enable_softaculous_auto_upgrade "$OPT_APPLY" || true
    stage_modsecurity_rules "$OPT_APPLY" || true
    if restart_openlitespeed_if_needed "$OPT_APPLY"; then
        if [ "$OPT_APPLY" = "1" ] && [ "$WP2SHELL_RESTART_REQUIRED" = "1" ]; then
            verify_hardening_after_restart
        fi
    fi
    return 0
}

command_restore() {
    local quarantine_root="${WP2SHELL_QUARANTINE_DIR:-/var/lib/wp2shell/quarantine}/$OPT_RUN_ID"
    if [ ! -d "$quarantine_root" ]; then
        log_error "Geen quarantaine gevonden voor run $OPT_RUN_ID in $quarantine_root"
        return "$EXIT_USAGE"
    fi
    local manifests
    manifests=$(mktemp -t wp2shell-restore.XXXXXXXX) || return "$EXIT_INTERNAL"
    register_temp_cleanup "$manifests"
    local find_status=0
    "${WP2SHELL_FIND:-find}" -P "$quarantine_root" -mindepth 2 -maxdepth 2 -type f -name 'manifest.ndjson' -print0 > "$manifests" 2>/dev/null || find_status=$?
    if [ "$find_status" -ne 0 ]; then
        log_error "Het doorzoeken van $quarantine_root gaf exitcode $find_status, de lijst met manifesten is mogelijk onvolledig"
        log_error "Er wordt niets teruggezet, want een onvolledige lijst laat bestanden ongemerkt in quarantaine staan"
        return "$EXIT_INTERNAL"
    fi
    if [ ! -s "$manifests" ]; then
        log_error "Geen manifest gevonden onder $quarantine_root"
        return "$EXIT_USAGE"
    fi
    local manifest failures=0 handled=0
    while IFS= read -r -d '' manifest; do
        handled=$((handled + 1))
        if [ "$OPT_APPLY" != "1" ]; then
            log_info "Zou terugzetten uit $manifest"
            preview_restore_from_manifest "$manifest" "$OPT_FILTER"
            continue
        fi
        log_info "Terugzetten uit $manifest"
        if ! restore_from_manifest "$manifest" "$OPT_FILTER"; then
            failures=$((failures + 1))
        fi
    done < "$manifests"
    if [ "$OPT_APPLY" != "1" ]; then
        log_info "$handled manifesten bekeken, er is niets teruggezet omdat --apply ontbreekt"
        return 0
    fi
    log_info "$handled manifesten verwerkt, $failures met fouten"
    if [ "$failures" -gt 0 ]; then
        return "$EXIT_INTERNAL"
    fi
    return 0
}

command_report() {
    if [ -z "$OPT_RUN_ID" ]; then
        log_error "report vereist --run-id van een eerdere run"
        return "$EXIT_USAGE"
    fi
    if [ ! -s "$WP2SHELL_SITES_FILE" ]; then
        log_error "Geen resultaten gevonden voor run $OPT_RUN_ID"
        return "$EXIT_USAGE"
    fi
    return 0
}

finalize_run() {
    WP2SHELL_FINISHED_AT=$(timestamp_iso)
    write_report_json "$WP2SHELL_REPORT_JSON"
    render_dutch_summary "$WP2SHELL_REPORT_TEXT"
    log_info "Rapport geschreven naar $WP2SHELL_RUN_DIR"
    if [ "$OPT_NO_MAIL" != "1" ]; then
        local subject
        subject="wp2shell rapport $(hostname -s 2>/dev/null || hostname): $(worst_severity_from_findings)"
        send_report_mail "${WP2SHELL_REPORT_EMAIL:-}" "$subject" \
            "$WP2SHELL_REPORT_TEXT" "$WP2SHELL_REPORT_JSON" || true
    fi
    cat -- "$WP2SHELL_REPORT_TEXT"
    return 0
}

main() {
    install_cleanup_trap
    parse_arguments "$@"
    validate_arguments
    local config_path=${OPT_CONFIG:-$WP2SHELL_ROOT/config/wp2shell.conf}
    load_configuration "$config_path"
    apply_option_overrides
    check_dependencies
    setup_run_environment
    warn_about_privileges
    log_info "wp2shell $WP2SHELL_TOOLKIT_VERSION, subcommando $OPT_SUBCOMMAND, run $WP2SHELL_RUN_ID"
    if [ "$OPT_APPLY" = "1" ]; then
        log_warn "Wijzigende modus is ingeschakeld met --apply"
    else
        log_info "Rapportagemodus, er wordt niets gewijzigd"
    fi
    if [ "$OPT_SUBCOMMAND" != "report" ]; then
        if ! acquire_run_lock "${WP2SHELL_LOCK_FILE:-/var/run/wp2shell.lock}"; then
            die "$EXIT_LOCKED" "Er draait al een wp2shell-run, deze run stopt"
        fi
    fi
    local subcommand_status=0
    case $OPT_SUBCOMMAND in
        scan) command_scan || subcommand_status=$? ;;
        clean) command_clean || subcommand_status=$? ;;
        harden) command_harden || subcommand_status=$? ;;
        report) command_report || subcommand_status=$? ;;
        restore) command_restore || subcommand_status=$? ;;
    esac
    if [ "$subcommand_status" -ne 0 ]; then
        release_run_lock
        die "$subcommand_status" "Het subcommando $OPT_SUBCOMMAND is gestopt met exitcode $subcommand_status"
    fi
    if [ "$OPT_SUBCOMMAND" = "restore" ]; then
        release_run_lock
        log_info "Terugzetten afgerond"
        exit "$EXIT_OK"
    fi
    finalize_run
    release_run_lock
    local worst
    worst=$(worst_severity_from_findings)
    log_info "Zwaarste bevinding: $worst"
    exit "$(severity_exit_code "$worst")"
}

main "$@"
