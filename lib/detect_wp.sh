WP2SHELL_DETECT_WP_LOADED=1

WP2SHELL_DETECT_WP_FAILED_CHECKS=()
WP2SHELL_DETECT_WP_CHECK_COMPLETED=0

WP2SHELL_DETECT_WP_MODULE_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ]; then
    WP2SHELL_DETECT_WP_MODULE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd) \
        || WP2SHELL_DETECT_WP_MODULE_DIR=""
fi

WP2SHELL_DETECT_WP_WORK_DIR=""
WP2SHELL_DETECT_WP_TABLE_PREFIX=""
WP2SHELL_DETECT_WP_ACTIVE_PLUGINS_FILE=""
WP2SHELL_DETECT_WP_ITEM_BUDGET=0
WP2SHELL_DETECT_WP_IOC_LOADED=0
WP2SHELL_DETECT_WP_PATTERNS_LOADED=0
WP2SHELL_DETECT_WP_SIGNAL_SEVERITY=""
WP2SHELL_DETECT_WP_SIGNAL_CONFIDENCE=""
WP2SHELL_DETECT_WP_SIGNAL_EVIDENCE=""

declare -gA WP2SHELL_DETECT_WP_IOC_HASHES=()
WP2SHELL_DETECT_WP_STRONG_PATTERNS=()

WP2SHELL_DETECT_WP_OPTION_MARKERS=(
    'eval('
    'base64_decode('
    'gzinflate('
    '<?php'
)

WP2SHELL_DETECT_WP_GENERIC_MARKERS=(
    'eval('
    'base64_decode('
    'gzinflate('
    'gzuncompress('
    'str_rot13('
    'assert('
    'create_function('
    '<?php'
)

if [ -z "${WP2SHELL_SUSPECT_ADMIN_LOGIN_PREFIXES+x}" ]; then
    WP2SHELL_SUSPECT_ADMIN_LOGIN_PREFIXES=(
        "wp2_"
        "w2s_"
        "wpsvc_"
    )
fi

if [ -z "${WP2SHELL_SUSPECT_ADMIN_EMAIL_DOMAINS+x}" ]; then
    WP2SHELL_SUSPECT_ADMIN_EMAIL_DOMAINS=(
        "@wp2shell."
        "@shellcode."
    )
fi

if [ -z "${WP2SHELL_KNOWN_CRON_HOOKS+x}" ]; then
    WP2SHELL_KNOWN_CRON_HOOKS=(
        "delete_expired_transients"
        "do_pings"
        "importer_scheduled_cleanup"
        "publish_future_post"
        "recovery_mode_clean_expired_keys"
        "wp_https_detection"
        "wp_maybe_auto_update"
        "wp_privacy_delete_old_export_files"
        "wp_scheduled_auto_draft_delete"
        "wp_scheduled_delete"
        "wp_site_health_scheduled_check"
        "wp_update_plugins"
        "wp_update_themes"
        "wp_update_user_counts"
        "wp_delete_temp_updater_backups"
        "wp_version_check"
    )
fi

detect_wp_ioc_directory() {
    local candidate
    if [ -n "${WP2SHELL_IOC_DIR:-}" ] && [ -d "$WP2SHELL_IOC_DIR" ]; then
        printf '%s' "$WP2SHELL_IOC_DIR"
        return 0
    fi
    if [ -n "${WP2SHELL_ROOT:-}" ] && [ -d "$WP2SHELL_ROOT/config/iocs" ]; then
        printf '%s' "$WP2SHELL_ROOT/config/iocs"
        return 0
    fi
    if [ -n "$WP2SHELL_DETECT_WP_MODULE_DIR" ]; then
        candidate="$WP2SHELL_DETECT_WP_MODULE_DIR/../config/iocs"
        if [ -d "$candidate" ]; then
            printf '%s' "$candidate"
            return 0
        fi
    fi
    return 1
}

detect_wp_load_ioc_hashes() {
    if [ "$WP2SHELL_DETECT_WP_IOC_LOADED" = "1" ]; then
        return 0
    fi
    WP2SHELL_DETECT_WP_IOC_LOADED=1
    local directory hashes_file line algorithm digest level category source
    if ! directory=$(detect_wp_ioc_directory); then
        log_debug "Geen IOC-map gevonden, hashvergelijking wordt overgeslagen"
        return 0
    fi
    hashes_file="$directory/hashes.txt"
    if [ ! -r "$hashes_file" ]; then
        log_debug "IOC-hashbestand ontbreekt: $hashes_file"
        return 0
    fi
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%$'\r'}
        if [ -z "$line" ]; then
            continue
        fi
        IFS=':' read -r algorithm digest level category source <<< "$line"
        if [ -z "$algorithm" ] || [ -z "$digest" ]; then
            continue
        fi
        case $algorithm in
            sha1|sha256) ;;
            *) continue ;;
        esac
        digest=${digest,,}
        WP2SHELL_DETECT_WP_IOC_HASHES["$algorithm:$digest"]="${category:-onbekend} (${source:-onbekende bron}, niveau ${level:-onbekend})"
    done < "$hashes_file"
    log_debug "IOC-hashes geladen: ${#WP2SHELL_DETECT_WP_IOC_HASHES[@]}"
    return 0
}

detect_wp_load_code_patterns() {
    if [ "$WP2SHELL_DETECT_WP_PATTERNS_LOADED" = "1" ]; then
        return 0
    fi
    WP2SHELL_DETECT_WP_PATTERNS_LOADED=1
    local directory patterns_file line category remainder level pattern
    if ! directory=$(detect_wp_ioc_directory); then
        return 0
    fi
    patterns_file="$directory/code-patterns.txt"
    if [ ! -r "$patterns_file" ]; then
        return 0
    fi
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%$'\r'}
        if [ -z "$line" ]; then
            continue
        fi
        category=${line%%:*}
        remainder=${line#*:}
        level=${remainder%%:*}
        pattern=${remainder#*:}
        if [ -z "$pattern" ] || [ "$level" != "high" ]; then
            continue
        fi
        case $category in
            unpack|backdoor|prepend) WP2SHELL_DETECT_WP_STRONG_PATTERNS+=("$pattern") ;;
        esac
    done < "$patterns_file"
    log_debug "Sterke codepatronen geladen: ${#WP2SHELL_DETECT_WP_STRONG_PATTERNS[@]}"
    return 0
}

detect_wp_file_ioc_label() {
    local path=$1 digest label
    detect_wp_load_ioc_hashes
    if [ ! -f "$path" ] || [ -L "$path" ]; then
        return 1
    fi
    digest=$(file_sha1 "$path") || digest=''
    if [ -n "$digest" ]; then
        label=${WP2SHELL_DETECT_WP_IOC_HASHES["sha1:${digest,,}"]:-}
        if [ -n "$label" ]; then
            printf '%s' "$label"
            return 0
        fi
    fi
    if have_command sha256sum; then
        digest=$(sha256sum -- "$path" 2>/dev/null | cut -d' ' -f1) || digest=''
        if [ -n "$digest" ]; then
            label=${WP2SHELL_DETECT_WP_IOC_HASHES["sha256:${digest,,}"]:-}
            if [ -n "$label" ]; then
                printf '%s' "$label"
                return 0
            fi
        fi
    fi
    return 1
}

detect_wp_strong_pattern_match() {
    local text=$1 pattern
    detect_wp_load_code_patterns
    if [ "${#WP2SHELL_DETECT_WP_STRONG_PATTERNS[@]}" -eq 0 ]; then
        return 1
    fi
    for pattern in "${WP2SHELL_DETECT_WP_STRONG_PATTERNS[@]}"; do
        case $text in
            *"$pattern"*)
                printf '%s' "$pattern"
                return 0
                ;;
        esac
    done
    return 1
}

detect_wp_generic_marker_count() {
    local text=$1 marker total=0
    for marker in "${WP2SHELL_DETECT_WP_GENERIC_MARKERS[@]}"; do
        case $text in
            *"$marker"*) total=$((total + 1)) ;;
        esac
    done
    printf '%s' "$total"
}

detect_wp_evaluate_text_signals() {
    local text=$1 strong count
    WP2SHELL_DETECT_WP_SIGNAL_SEVERITY="$SEVERITY_LOW"
    WP2SHELL_DETECT_WP_SIGNAL_CONFIDENCE="$CONFIDENCE_HEURISTIC"
    WP2SHELL_DETECT_WP_SIGNAL_EVIDENCE=""
    if strong=$(detect_wp_strong_pattern_match "$text"); then
        WP2SHELL_DETECT_WP_SIGNAL_SEVERITY="$SEVERITY_CRITICAL"
        WP2SHELL_DETECT_WP_SIGNAL_CONFIDENCE="$CONFIDENCE_HIGH"
        WP2SHELL_DETECT_WP_SIGNAL_EVIDENCE="Bevestigd IOC-patroon aangetroffen: $strong."
        return 0
    fi
    count=$(detect_wp_generic_marker_count "$text")
    if [ "$count" -ge 2 ]; then
        WP2SHELL_DETECT_WP_SIGNAL_SEVERITY="$SEVERITY_HIGH"
        WP2SHELL_DETECT_WP_SIGNAL_EVIDENCE="Meerdere generieke obfuscatiepatronen aangetroffen: $count."
        return 0
    fi
    if [ "$count" -eq 1 ]; then
        WP2SHELL_DETECT_WP_SIGNAL_SEVERITY="$SEVERITY_MEDIUM"
        WP2SHELL_DETECT_WP_SIGNAL_EVIDENCE="Een enkel generiek obfuscatiepatroon aangetroffen."
        return 0
    fi
    return 0
}

detect_wp_join_with() {
    local separator=$1
    shift
    local result='' item first=1
    for item in "$@"; do
        if [ "$first" = "1" ]; then
            result="$item"
            first=0
        else
            result="$result$separator$item"
        fi
    done
    printf '%s' "$result"
}

detect_wp_reset_item_budget() {
    WP2SHELL_DETECT_WP_ITEM_BUDGET=${WP2SHELL_DETECT_WP_MAX_ITEM_FINDINGS:-40}
    case $WP2SHELL_DETECT_WP_ITEM_BUDGET in
        ''|*[!0-9]*) WP2SHELL_DETECT_WP_ITEM_BUDGET=40 ;;
    esac
    return 0
}

detect_wp_consume_item_budget() {
    if [ "$WP2SHELL_DETECT_WP_ITEM_BUDGET" -le 0 ]; then
        return 1
    fi
    WP2SHELL_DETECT_WP_ITEM_BUDGET=$((WP2SHELL_DETECT_WP_ITEM_BUDGET - 1))
    return 0
}

detect_wp_shorten() {
    local text=$1 limit=${2:-${WP2SHELL_HEURISTIC_EVIDENCE_CHARS:-200}}
    case $limit in
        ''|*[!0-9]*) limit=200 ;;
    esac
    if [ "${#text}" -le "$limit" ]; then
        printf '%s' "$text"
        return 0
    fi
    printf '%s...' "${text:0:$limit}"
    return 0
}

detect_wp_work_file() {
    printf '%s/%s' "$WP2SHELL_DETECT_WP_WORK_DIR" "$1"
}

detect_wp_sql_pattern_is_safe() {
    local raw=$1
    if [ -z "$raw" ]; then
        return 1
    fi
    case $raw in
        *\\*) return 1 ;;
        *[[:cntrl:]]*) return 1 ;;
    esac
    return 0
}

detect_wp_sql_quote_pattern() {
    local raw=$1
    printf '%s' "${raw//\'/\'\'}"
}

detect_wp_identifier_is_safe() {
    local raw=$1
    case $raw in
        '') return 1 ;;
        *[!A-Za-z0-9_]*) return 1 ;;
    esac
    return 0
}

detect_wp_datetime_to_number() {
    local raw=$1 digits
    digits=${raw//[^0-9]/}
    if [ "${#digits}" -eq 8 ]; then
        digits="${digits}000000"
    fi
    if [ "${#digits}" -ne 14 ]; then
        return 1
    fi
    printf '%s' "$digits"
    return 0
}

detect_wp_exposure_window_datetime() {
    local raw=${WP2SHELL_EXPOSURE_WINDOW_START:-} normalized
    if [ -z "$raw" ]; then
        return 1
    fi
    normalized=${raw//T/ }
    normalized=${normalized%Z}
    normalized=${normalized%% *[+-][0-9][0-9]:[0-9][0-9]}
    case $normalized in
        [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9])
            normalized="$normalized 00:00:00"
            ;;
        [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]' '[0-9][0-9]:[0-9][0-9]:[0-9][0-9]) ;;
        *) return 1 ;;
    esac
    printf '%s' "$normalized"
    return 0
}

detect_wp_url_host() {
    local url=$1 host
    host=${url#*://}
    host=${host%%/*}
    host=${host##*@}
    host=${host%%:*}
    printf '%s' "${host,,}"
}

detect_wp_host_matches_domain() {
    local host=${1,,} domain=${2,,}
    if [ -z "$host" ] || [ -z "$domain" ]; then
        return 1
    fi
    case $host in
        "$domain") return 0 ;;
        *".$domain") return 0 ;;
    esac
    return 1
}

detect_wp_json_objects_to_lines() {
    local source_file=$1
    php -r '
        $raw = file_get_contents($argv[1]);
        if ($raw === false) { exit(1); }
        $data = json_decode($raw, true);
        if (!is_array($data)) { exit(1); }
        $flags = JSON_UNESCAPED_SLASHES;
        if (defined("JSON_INVALID_UTF8_SUBSTITUTE")) { $flags |= JSON_INVALID_UTF8_SUBSTITUTE; }
        foreach ($data as $item) {
            if (!is_array($item)) { continue; }
            $line = json_encode($item, $flags);
            if ($line === false) { continue; }
            echo $line, "\n";
        }
    ' "$source_file"
}

detect_wp_json_values_to_lines() {
    local source_file=$1
    php -r '
        $raw = file_get_contents($argv[1]);
        if ($raw === false) { exit(1); }
        $data = json_decode($raw, true);
        if (!is_array($data)) { exit(1); }
        foreach ($data as $value) {
            if (is_array($value) || is_object($value) || is_null($value)) { continue; }
            $text = str_replace(array("\r", "\n", "\t"), " ", (string) $value);
            if ($text === "") { continue; }
            echo $text, "\n";
        }
    ' "$source_file"
}

detect_wp_capture() {
    local site_path=$1 owner_user=$2 label=$3
    shift 3
    local out err status=0
    out=$(detect_wp_work_file "$label.out")
    err=$(detect_wp_work_file "$label.err")
    : > "$out"
    : > "$err"
    wp_run "$owner_user" "$site_path" "$@" >"$out" 2>"$err" || status=$?
    printf '%s' "$status"
    return 0
}

detect_wp_first_error_line() {
    local file=$1 line
    if [ ! -s "$file" ]; then
        return 1
    fi
    while IFS= read -r line || [ -n "$line" ]; do
        case $line in
            Error:*)
                printf '%s' "$(detect_wp_shorten "$line" 300)"
                return 0
                ;;
        esac
    done < "$file"
    return 1
}

detect_wp_classify_checksum_line() {
    local line=$1
    case $line in
        *"skipping"*) printf 'skipped' ; return 0 ;;
        *"Could not retrieve the checksums"*) printf 'skipped' ; return 0 ;;
        *"should not exist"*) printf 'added' ; return 0 ;;
        *"doesn't verify against checksum"*) printf 'modified' ; return 0 ;;
        *"does not match"*) printf 'modified' ; return 0 ;;
        *"was added"*) printf 'added' ; return 0 ;;
        *"doesn't exist"*) printf 'missing' ; return 0 ;;
    esac
    return 1
}

detect_wp_checksum_line_path() {
    local line=$1 extracted='' marker
    for marker in \
        "File should not exist: " \
        "File doesn't verify against checksum: " \
        "File doesn't exist: "
    do
        case $line in
            *"$marker"*)
                extracted=${line#*"$marker"}
                break
                ;;
        esac
    done
    if [ -z "$extracted" ]; then
        for marker in "should not exist: " "verify against checksum: " "doesn't exist: "; do
            case $line in
                *"$marker"*)
                    extracted=${line#*"$marker"}
                    break
                    ;;
            esac
        done
    fi
    extracted=${extracted%$'\r'}
    if [ -z "$extracted" ]; then
        return 1
    fi
    printf '%s' "$extracted"
    return 0
}

detect_wp_skipped_plugin_slug() {
    local line=$1 remainder
    case $line in
        *"of plugin "*)
            remainder=${line##*"of plugin "}
            remainder=${remainder%%,*}
            ;;
        *"plugin "*)
            remainder=${line##*"plugin "}
            remainder=${remainder%%,*}
            remainder=${remainder%%.*}
            ;;
        *) return 1 ;;
    esac
    if [ -z "$remainder" ]; then
        return 1
    fi
    printf '%s' "$remainder"
    return 0
}

detect_wp_absolute_candidate() {
    local raw=$1 site_path=$2 plugins_dir=$3
    case $raw in
        /*)
            printf '%s' "$raw"
            return 0
            ;;
    esac
    if [ -n "$plugins_dir" ] && [ -e "$plugins_dir/$raw" ]; then
        printf '%s' "$plugins_dir/$raw"
        return 0
    fi
    if [ -e "$site_path/$raw" ]; then
        printf '%s' "$site_path/$raw"
        return 0
    fi
    if [ -n "$plugins_dir" ]; then
        printf '%s/%s' "$plugins_dir" "$raw"
        return 0
    fi
    printf '%s/%s' "$site_path" "$raw"
    return 0
}

detect_wp_path_is_core_directory() {
    local relative=$1
    case $relative in
        wp-admin/*|wp-includes/*) return 0 ;;
        */wp-admin/*|*/wp-includes/*) return 0 ;;
    esac
    return 1
}

detect_wp_path_is_executable_php() {
    local candidate=${1,,}
    case $candidate in
        *.php|*.php3|*.php4|*.php5|*.php7|*.php8|*.phtml|*.phar|*.inc|*.pht) return 0 ;;
    esac
    return 1
}

detect_wp_cli_version() {
    local site_path=$1 owner_user=$2 raw
    raw=$(wp_run "$owner_user" "$site_path" cli version 2>/dev/null) || raw=''
    raw=${raw%%$'\n'*}
    raw=${raw#WP-CLI }
    raw=${raw// /}
    if [ -z "$raw" ]; then
        return 1
    fi
    printf '%s' "$raw"
    return 0
}

detect_wp_core_version() {
    local site_path=$1 owner_user=$2 raw
    raw=$(wp_run "$owner_user" "$site_path" core version 2>/dev/null) || raw=''
    raw=${raw%%$'\n'*}
    raw=${raw// /}
    case $raw in
        '') return 1 ;;
        *[!0-9A-Za-z.-]*) return 1 ;;
    esac
    printf '%s' "$raw"
    return 0
}

detect_wp_site_locale() {
    local site_path=$1 owner_user=$2 raw
    raw=$(wp_run "$owner_user" "$site_path" option get WPLANG 2>/dev/null) || raw=''
    raw=${raw%%$'\n'*}
    raw=${raw// /}
    case $raw in
        '') return 1 ;;
        *[!A-Za-z_]*) return 1 ;;
    esac
    printf '%s' "$raw"
    return 0
}

detect_wp_plugins_directory() {
    local site_path=$1 owner_user=$2 value
    value=$(wp_run "$owner_user" "$site_path" plugin path 2>/dev/null) || value=''
    value=${value%%$'\n'*}
    if [ -n "$value" ] && [ -d "$value" ]; then
        printf '%s' "$value"
        return 0
    fi
    if [ -d "$site_path/wp-content/plugins" ]; then
        printf '%s' "$site_path/wp-content/plugins"
        return 0
    fi
    return 1
}

detect_wp_content_directory() {
    local site_path=$1 owner_user=$2 plugins_dir
    if plugins_dir=$(detect_wp_plugins_directory "$site_path" "$owner_user"); then
        printf '%s' "$(dirname -- "$plugins_dir")"
        return 0
    fi
    if [ -d "$site_path/wp-content" ]; then
        printf '%s' "$site_path/wp-content"
        return 0
    fi
    return 1
}

detect_wp_path_is_operational_artifact() {
    local relative=$1
    local base=${relative##*/}
    case $base in
        error_log|php_errorlog|error.log|debug.log|.htaccess|.htpasswd|.maintenance|.ftpquota|.DS_Store|Thumbs.db)
            return 0
            ;;
        robots.txt|ads.txt|app-ads.txt|favicon.ico|sitemap.xml|sitemap_index.xml|browserconfig.xml|humans.txt|security.txt)
            return 0
            ;;
        google*.html|BingSiteAuth.xml|pinterest-*.html|yandex_*.html)
            return 0
            ;;
    esac
    case $relative in
        .well-known/*|*/.well-known/*) return 0 ;;
        *.log|*.log.[0-9]|*.gz) return 0 ;;
    esac
    return 1
}

detect_wp_report_checksum_entry() {
    local site_path=$1 kind=$2 raw_path=$3 line=$4 scope=$5 plugins_dir=$6
    local absolute relative severity confidence category title detail remediation
    local ioc_label='' digest='' evidence
    absolute=$(detect_wp_absolute_candidate "$raw_path" "$site_path" "$plugins_dir")
    relative=$raw_path
    evidence=$(detect_wp_shorten "$line" 300)
    if [ -n "$absolute" ] && is_allowlisted_path "$absolute"; then
        log_debug "Bestand staat op de allowlist en wordt niet gerapporteerd: $absolute"
        return 0
    fi
    if [ -f "$absolute" ] && [ ! -L "$absolute" ]; then
        digest=$(file_sha1 "$absolute") || digest=''
        ioc_label=$(detect_wp_file_ioc_label "$absolute") || ioc_label=''
    fi
    case $kind in
        added)
            if [ "$scope" = "core" ]; then
                category="core-file-added"
            else
                category="plugin-file-added"
            fi
            if [ -n "$ioc_label" ]; then
                severity="$SEVERITY_CRITICAL"
                confidence="$CONFIDENCE_HIGH"
                title="Bevestigde webshell aangetroffen op basis van hashvergelijking"
                detail="Dit bestand hoort niet bij de officiele release en de hash komt overeen met een gepubliceerde IOC ($ioc_label). Dit is geen vermoeden maar een bevestigde besmetting."
                remediation="Behandel deze site als gecompromitteerd. Plaats het bestand in quarantaine via de opschoonstap, roteer databasewachtwoorden en salts, en controleer alle beheerdersaccounts."
            elif detect_wp_path_is_operational_artifact "$relative"; then
                severity="$SEVERITY_INFO"
                confidence="$CONFIDENCE_HEURISTIC"
                title="Bekend beheerbestand dat niet bij de release hoort"
                detail="Dit bestand komt niet voor in de officiele checksumlijst, maar de naam hoort bij een bekend beheer- of serverartefact. PHP schrijft error_log zelf weg zodra logging aan staat, en DirectAdmin plaatst een eigen .htaccess bij wachtwoordbeveiliging. Dit is vrijwel altijd normaal."
                remediation="Geen actie nodig, tenzij de inhoud verdacht is."
            elif [ "$scope" = "core" ] && detect_wp_path_is_core_directory "$relative" && detect_wp_path_is_executable_php "$relative"; then
                severity="$SEVERITY_CRITICAL"
                confidence="$CONFIDENCE_HIGH"
                title="Onbekend PHP-bestand in de WordPress-core aangetroffen"
                detail="wp core verify-checksums meldt dat dit uitvoerbare PHP-bestand niet in de officiele WordPress-release voorkomt, terwijl het wel in wp-admin of wp-includes staat. Die mappen horen uitsluitend corebestanden te bevatten, dus twee signalen vallen hier samen: het hoort niet bij de release en het is uitvoerbare code op een plek waar niets anders thuishoort. In deze aanval is dat de meest voorkomende dropper. Let op: verify-checksums controleert nooit wp-content, dus dit is geen volledige integriteitscontrole van de hele boom."
                remediation="Bekijk het bestand en plaats het via de opschoonstap in quarantaine. Verwijder niets met de hand en bewaar het bewijs."
            elif [ "$scope" = "core" ] && detect_wp_path_is_core_directory "$relative"; then
                severity="$SEVERITY_HIGH"
                confidence="$CONFIDENCE_HEURISTIC"
                title="Onbekend bestand in een core-map aangetroffen"
                detail="Dit bestand staat in wp-admin of wp-includes maar hoort niet bij de officiele release. Het is geen uitvoerbare PHP, dus het gaat vaak om een logbestand, een backup of een artefact van een plugin. Beoordeel het handmatig."
                remediation="Controleer de herkomst van dit bestand en zet het zo nodig via de opschoonstap in quarantaine."
            elif detect_wp_path_is_executable_php "$relative"; then
                severity="$SEVERITY_HIGH"
                confidence="$CONFIDENCE_HEURISTIC"
                title="Onbekend PHP-bestand aangetroffen dat niet bij de release hoort"
                detail="Dit uitvoerbare PHP-bestand staat op schijf maar komt niet voor in de officiele checksumlijst. Let op dat verify-checksums met --include-root de hele webroot doorloopt, dus een tweede applicatie naast WordPress, een hernoemde contentmap of een eigen maatwerkbestand komt hier ook in terecht. Daarom blijft dit heuristisch en gaat het niet automatisch in quarantaine."
                remediation="Beoordeel de herkomst van dit bestand. Hoort het bij de klant, zet het dan op de allowlist in de configuratie."
            else
                severity="$SEVERITY_MEDIUM"
                confidence="$CONFIDENCE_HEURISTIC"
                title="Onverwacht bestand in de webroot dat niet bij WordPress hoort"
                detail="Dit bestand komt niet voor in de officiele checksumlijst. Het is geen uitvoerbare PHP, dus het gaat vaak om een eigen bestand van de klant, bijvoorbeeld een verificatiebestand van een zoekmachine. Handmatig beoordelen."
                remediation="Controleer of dit bestand van de klant afkomstig is en zet het zo nodig op de allowlist."
            fi
            ;;
        modified)
            if [ "$scope" = "core" ]; then
                category="core-file-modified"
            else
                category="plugin-file-modified"
            fi
            if [ "$scope" = "core" ]; then
                severity="$SEVERITY_HIGH"
                confidence="$CONFIDENCE_HIGH"
                title="Core-bestand wijkt af van de officiele checksum"
                detail="De inhoud van dit core-bestand komt niet overeen met de officiele WordPress-release. Een gewijzigd core-bestand is bij deze aanval een bekende plek voor een injectie of een tweede achterdeur. Let op: verify-checksums controleert nooit wp-content."
                remediation="Vergelijk het bestand met de officiele release en herstel de core met wp core update --version=<exacte versie> --force. Bewaar eerst het bewijs."
            else
                severity="$SEVERITY_HIGH"
                confidence="$CONFIDENCE_HEURISTIC"
                title="Pluginbestand wijkt af van de checksum van wordpress.org"
                detail="De inhoud van dit pluginbestand komt niet overeen met de versie die op wordpress.org staat. Dat kan een injectie zijn, maar ook een bewuste aanpassing door een ontwikkelaar. Daarom blijft dit heuristisch en mag het niet automatisch in quarantaine."
                remediation="Vergelijk het bestand met de officiele plugin-release en beoordeel de wijziging handmatig."
            fi
            ;;
        missing)
            if [ "$scope" = "core" ]; then
                category="core-file-missing"
            else
                category="plugin-file-missing"
            fi
            severity="$SEVERITY_MEDIUM"
            confidence="$CONFIDENCE_HEURISTIC"
            title="Bestand uit de officiele release ontbreekt"
            detail="Dit bestand hoort bij de officiele release maar staat niet op schijf. Dat gebeurt vaak door een hardeningscript dat bestanden weghaalt, maar het kan ook wijzen op een mislukte of onvolledige update."
            remediation="Herstel de installatie met een volledige herinstallatie van de betreffende versie wanneer de klant deze bestanden niet bewust heeft verwijderd."
            ;;
        *)
            return 0
            ;;
    esac
    record_finding \
        "site=$site_path" \
        "severity=$severity" \
        "confidence=$confidence" \
        "category=$category" \
        "title=$title" \
        "detail=$detail" \
        "file=$absolute" \
        "sha1=$digest" \
        "evidence=$evidence" \
        "remediation=$remediation"
    return 0
}

detect_wp_core_checksums() {
    local site_path=$1 owner_user=$2
    WP2SHELL_DETECT_WP_CORE_ADDED=0
    WP2SHELL_DETECT_WP_CORE_MODIFIED=0
    WP2SHELL_DETECT_WP_CORE_MISSING=0
    WP2SHELL_DETECT_WP_CORE_STATUS='overgeslagen'
    if [ "${WP2SHELL_SCAN_CORE_CHECKSUMS:-1}" != "1" ]; then
        log_debug "Core-checksumcontrole staat uit in de configuratie"
        return 0
    fi
    local -a arguments=(core verify-checksums --include-root)
    local core_version locale
    if core_version=$(detect_wp_core_version "$site_path" "$owner_user"); then
        arguments+=("--version=$core_version")
    else
        log_warn "Kan de exacte coreversie niet vaststellen voor $site_path"
    fi
    if locale=$(detect_wp_site_locale "$site_path" "$owner_user"); then
        arguments+=("--locale=$locale")
    fi
    local status out err
    status=$(detect_wp_capture "$site_path" "$owner_user" core-checksums "${arguments[@]}")
    out=$(detect_wp_work_file core-checksums.out)
    err=$(detect_wp_work_file core-checksums.err)
    WP2SHELL_DETECT_WP_CORE_STATUS="exitcode $status"
    if [ ! -s "$out" ] && [ ! -s "$err" ]; then
        WP2SHELL_DETECT_WP_CORE_STATUS="geen uitvoer, exitcode $status"
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=core-checksums-unavailable" \
            "title=De core-integriteitscontrole heeft geen resultaat opgeleverd" \
            "detail=wp core verify-checksums leverde geen enkele uitvoer op en eindigde met exitcode $status. Dat wijst op een tijdslimiet, ontbrekende uitgaande verbinding naar api.wordpress.org, of een afgebroken proces. Deze installatie is dus niet op core-integriteit gecontroleerd en mag niet als schoon gelezen worden." \
            "remediation=Draai wp core verify-checksums --include-root handmatig op deze site en controleer of de server api.wordpress.org kan bereiken."
        detect_wp_mark_check_complete
        return 0
    fi
    local error_line
    if error_line=$(detect_wp_first_error_line "$err"); then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=core-checksums-error" \
            "title=De core-integriteitscontrole meldde een fout" \
            "detail=WP-CLI gaf een foutmelding tijdens wp core verify-checksums. De uitkomst van deze controle is daarmee onvolledig en deze installatie mag niet als schoon gelezen worden." \
            "evidence=$error_line" \
            "remediation=Draai het commando handmatig en los de gemelde fout op voordat het rapport als dekkend wordt beschouwd."
    fi
    detect_wp_reset_item_budget
    local -A seen_entries=()
    local source_file line kind raw_path key unparsed=0
    local unparsed_file
    unparsed_file=$(detect_wp_work_file core-unparsed.txt)
    : > "$unparsed_file"
    for source_file in "$err" "$out"; do
        if [ ! -s "$source_file" ]; then
            continue
        fi
        while IFS= read -r line || [ -n "$line" ]; do
            line=${line%$'\r'}
            case $line in
                '') continue ;;
                Success:*) continue ;;
                Error:*) continue ;;
            esac
            if ! kind=$(detect_wp_classify_checksum_line "$line"); then
                case $line in
                    Warning:*)
                        unparsed=$((unparsed + 1))
                        printf '%s\n' "$line" >> "$unparsed_file"
                        ;;
                esac
                continue
            fi
            if [ "$kind" = "skipped" ]; then
                continue
            fi
            if ! raw_path=$(detect_wp_checksum_line_path "$line"); then
                unparsed=$((unparsed + 1))
                printf '%s\n' "$line" >> "$unparsed_file"
                continue
            fi
            key="$kind|$raw_path"
            if [ -n "${seen_entries[$key]:-}" ]; then
                continue
            fi
            seen_entries[$key]=1
            case $kind in
                added) WP2SHELL_DETECT_WP_CORE_ADDED=$((WP2SHELL_DETECT_WP_CORE_ADDED + 1)) ;;
                modified) WP2SHELL_DETECT_WP_CORE_MODIFIED=$((WP2SHELL_DETECT_WP_CORE_MODIFIED + 1)) ;;
                missing) WP2SHELL_DETECT_WP_CORE_MISSING=$((WP2SHELL_DETECT_WP_CORE_MISSING + 1)) ;;
            esac
            if detect_wp_consume_item_budget; then
                detect_wp_report_checksum_entry "$site_path" "$kind" "$raw_path" "$line" core ""
            fi
        done < "$source_file"
    done
    if [ "$WP2SHELL_DETECT_WP_ITEM_BUDGET" -le 0 ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_HIGH" \
            "confidence=$CONFIDENCE_HEURISTIC" \
            "category=core-checksums-truncated" \
            "title=Te veel afwijkingen in de core om afzonderlijk te rapporteren" \
            "detail=De core-integriteitscontrole leverde meer afwijkingen op dan er afzonderlijk gerapporteerd worden. Toegevoegd: $WP2SHELL_DETECT_WP_CORE_ADDED, gewijzigd: $WP2SHELL_DETECT_WP_CORE_MODIFIED, ontbrekend: $WP2SHELL_DETECT_WP_CORE_MISSING." \
            "remediation=Bekijk de volledige uitvoer van wp core verify-checksums --include-root handmatig."
    fi
    if [ "$unparsed" -gt 0 ]; then
        local sample
        sample=$(head -c 400 -- "$unparsed_file" 2>/dev/null) || sample=''
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HEURISTIC" \
            "category=core-checksums-unparsed" \
            "title=Onbekende meldingen bij de core-integriteitscontrole" \
            "detail=Er zijn $unparsed waarschuwingen die niet in een bekend patroon passen. Dat kan betekenen dat de aanwezige WP-CLI andere teksten gebruikt dan de versie waarop deze toolkit is afgestemd. Deze meldingen zijn niet geclassificeerd en mogen niet als schoon gelezen worden." \
            "evidence=$(detect_wp_shorten "$sample" 300)" \
            "remediation=Bekijk de ruwe uitvoer handmatig en meld het afwijkende formaat zodat de parser bijgewerkt kan worden."
    fi
    log_info "Core-integriteit $site_path: toegevoegd $WP2SHELL_DETECT_WP_CORE_ADDED, gewijzigd $WP2SHELL_DETECT_WP_CORE_MODIFIED, ontbrekend $WP2SHELL_DETECT_WP_CORE_MISSING"
    detect_wp_mark_check_complete
    return 0
}

detect_wp_plugin_checksums() {
    local site_path=$1 owner_user=$2
    WP2SHELL_DETECT_WP_PLUGIN_SKIPPED=0
    WP2SHELL_DETECT_WP_PLUGIN_ISSUES=0
    WP2SHELL_DETECT_WP_PLUGIN_STATUS='overgeslagen'
    if [ "${WP2SHELL_SCAN_PLUGIN_CHECKSUMS:-1}" != "1" ]; then
        log_debug "Plugin-checksumcontrole staat uit in de configuratie"
        return 0
    fi
    local plugins_dir=''
    plugins_dir=$(detect_wp_plugins_directory "$site_path" "$owner_user") || plugins_dir=''
    local status out err
    status=$(detect_wp_capture "$site_path" "$owner_user" plugin-checksums plugin verify-checksums --all --format=json)
    out=$(detect_wp_work_file plugin-checksums.out)
    err=$(detect_wp_work_file plugin-checksums.err)
    if grep -q 'Parameter errors' -- "$err" 2>/dev/null; then
        log_debug "plugin verify-checksums accepteert --format niet, opnieuw zonder die vlag"
        status=$(detect_wp_capture "$site_path" "$owner_user" plugin-checksums plugin verify-checksums --all)
    fi
    WP2SHELL_DETECT_WP_PLUGIN_STATUS="exitcode $status"
    if [ ! -s "$out" ] && [ ! -s "$err" ]; then
        WP2SHELL_DETECT_WP_PLUGIN_STATUS="geen uitvoer, exitcode $status"
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=plugin-checksums-unavailable" \
            "title=De plugin-integriteitscontrole heeft geen resultaat opgeleverd" \
            "detail=wp plugin verify-checksums leverde geen uitvoer op en eindigde met exitcode $status. De plugins van deze installatie zijn dus niet geverifieerd en mogen niet als schoon gelezen worden." \
            "remediation=Draai wp plugin verify-checksums --all handmatig op deze site."
        detect_wp_mark_check_complete
        return 0
    fi
    local error_line
    if error_line=$(detect_wp_first_error_line "$err"); then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=plugin-checksums-error" \
            "title=De plugin-integriteitscontrole meldde een fout" \
            "detail=WP-CLI gaf een foutmelding tijdens wp plugin verify-checksums. De uitkomst van deze controle is daarmee onvolledig." \
            "evidence=$error_line" \
            "remediation=Draai het commando handmatig en los de gemelde fout op."
    fi
    detect_wp_reset_item_budget
    local -a skipped_slugs=()
    local line kind raw_path slug
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%$'\r'}
        case $line in
            ''|Success:*|Error:*) continue ;;
        esac
        if ! kind=$(detect_wp_classify_checksum_line "$line"); then
            continue
        fi
        if [ "$kind" = "skipped" ]; then
            if slug=$(detect_wp_skipped_plugin_slug "$line"); then
                skipped_slugs+=("$slug")
            else
                skipped_slugs+=("$(detect_wp_shorten "$line" 120)")
            fi
            continue
        fi
        if ! raw_path=$(detect_wp_checksum_line_path "$line"); then
            continue
        fi
        WP2SHELL_DETECT_WP_PLUGIN_ISSUES=$((WP2SHELL_DETECT_WP_PLUGIN_ISSUES + 1))
        if detect_wp_consume_item_budget; then
            detect_wp_report_checksum_entry "$site_path" "$kind" "$raw_path" "$line" plugin "$plugins_dir"
        fi
    done < "$err"
    if [ -s "$out" ]; then
        local rows_file
        rows_file=$(detect_wp_work_file plugin-checksums-rows.txt)
        if detect_wp_json_objects_to_lines "$out" > "$rows_file" 2>/dev/null; then
            local plugin_name file_name message combined
            while IFS= read -r line || [ -n "$line" ]; do
                if [ -z "$line" ]; then
                    continue
                fi
                plugin_name=$(json_extract_field "$line" plugin_name) || plugin_name=''
                file_name=$(json_extract_field "$line" file) || file_name=''
                message=$(json_extract_field "$line" message) || message=''
                if [ -z "$file_name" ]; then
                    continue
                fi
                combined="$message: $plugin_name/$file_name"
                if ! kind=$(detect_wp_classify_checksum_line "$message"); then
                    kind=modified
                fi
                WP2SHELL_DETECT_WP_PLUGIN_ISSUES=$((WP2SHELL_DETECT_WP_PLUGIN_ISSUES + 1))
                if detect_wp_consume_item_budget; then
                    detect_wp_report_checksum_entry "$site_path" "$kind" "$plugin_name/$file_name" \
                        "$combined" plugin "$plugins_dir"
                fi
            done < "$rows_file"
        fi
    fi
    WP2SHELL_DETECT_WP_PLUGIN_SKIPPED=${#skipped_slugs[@]}
    if [ "$WP2SHELL_DETECT_WP_PLUGIN_SKIPPED" -gt 0 ]; then
        local slug_list
        slug_list=$(detect_wp_join_with ", " "${skipped_slugs[@]}")
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HEURISTIC" \
            "category=plugin-checksums-skipped" \
            "title=Plugins zonder checksumdekking, niet geverifieerd" \
            "detail=Voor $WP2SHELL_DETECT_WP_PLUGIN_SKIPPED plugin(s) bestaat geen checksum op wordpress.org, meestal omdat het om een premium- of maatwerkplugin gaat. WP-CLI slaat die stil over en meldt daarna toch Success met exitcode 0. Overgeslagen is niet hetzelfde als schoon: een achterdeur in een van deze plugins komt in deze controle niet naar voren." \
            "evidence=$(detect_wp_shorten "$slug_list" 400)" \
            "remediation=Vergelijk deze plugins handmatig met een schone kopie van de leverancier of met een eerdere backup."
    fi
    log_info "Plugin-integriteit $site_path: afwijkingen $WP2SHELL_DETECT_WP_PLUGIN_ISSUES, niet geverifieerd $WP2SHELL_DETECT_WP_PLUGIN_SKIPPED"
    detect_wp_mark_check_complete
    return 0
}

detect_wp_theme_checksum_gap() {
    local site_path=$1 owner_user=$2
    local themes_file rows_file line name version status_value
    local -a descriptions=()
    themes_file=$(detect_wp_work_file themes.out)
    rows_file=$(detect_wp_work_file themes-rows.txt)
    if wp_run "$owner_user" "$site_path" theme list --fields=name,version,status --format=json \
        >"$themes_file" 2>/dev/null; then
        if detect_wp_json_objects_to_lines "$themes_file" > "$rows_file" 2>/dev/null; then
            while IFS= read -r line || [ -n "$line" ]; do
                if [ -z "$line" ]; then
                    continue
                fi
                name=$(json_extract_field "$line" name) || name=''
                version=$(json_extract_field "$line" version) || version=''
                status_value=$(json_extract_field "$line" status) || status_value=''
                if [ -n "$name" ]; then
                    descriptions+=("$name $version ($status_value)")
                fi
            done < "$rows_file"
        fi
    fi
    local evidence=''
    if [ "${#descriptions[@]}" -gt 0 ]; then
        evidence=$(detect_wp_join_with ", " "${descriptions[@]}")
    fi
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_INFO" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=theme-checksum-gap" \
        "title=Themas hebben geen checksumdekking" \
        "detail=Er bestaat geen wp theme verify-checksums in enige WP-CLI-versie, dus themabestanden zijn in deze controle niet op integriteit getoetst. Dat is relevant omdat droppers juist vaak in functions.php en 404.php van een thema belanden. Deze bevinding is informatief en zegt niets over besmetting." \
        "evidence=$(detect_wp_shorten "$evidence" 400)" \
        "remediation=Vergelijk de themabestanden handmatig met een schone kopie of met een backup van voor 17 juli 2026."
    detect_wp_mark_check_complete
    return 0
}

detect_wp_admin_rank_note() {
    local login=$1 email=$2 prefix domain
    local -a reasons=()
    if [ "${#WP2SHELL_SUSPECT_ADMIN_LOGIN_PREFIXES[@]}" -gt 0 ]; then
        for prefix in "${WP2SHELL_SUSPECT_ADMIN_LOGIN_PREFIXES[@]}"; do
            if [ -n "$prefix" ]; then
                case ${login,,} in
                    "${prefix,,}"*) reasons+=("loginprefix $prefix") ;;
                esac
            fi
        done
    fi
    if [ "${#WP2SHELL_SUSPECT_ADMIN_EMAIL_DOMAINS[@]}" -gt 0 ]; then
        for domain in "${WP2SHELL_SUSPECT_ADMIN_EMAIL_DOMAINS[@]}"; do
            if [ -n "$domain" ]; then
                case ${email,,} in
                    *"${domain,,}"*) reasons+=("e-maildomein $domain") ;;
                esac
            fi
        done
    fi
    if [ "${#reasons[@]}" -eq 0 ]; then
        return 1
    fi
    detect_wp_join_with ", " "${reasons[@]}"
    return 0
}

detect_wp_administrator_accounts() {
    local site_path=$1 owner_user=$2
    WP2SHELL_DETECT_WP_ADMIN_TOTAL=0
    WP2SHELL_DETECT_WP_ADMIN_IN_WINDOW=0
    WP2SHELL_DETECT_WP_ADMIN_TRUNCATED=0
    local admins_file rows_file status
    admins_file=$(detect_wp_work_file admins.out)
    rows_file=$(detect_wp_work_file admins-rows.txt)
    status=$(detect_wp_capture "$site_path" "$owner_user" admins \
        user list --role=administrator --fields=ID,user_login,user_email,user_registered --format=json)
    admins_file=$(detect_wp_work_file admins.out)
    if [ "$status" != "0" ] || [ ! -s "$admins_file" ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=admin-list-unavailable" \
            "title=De lijst met beheerders kon niet opgehaald worden" \
            "detail=wp user list voor de rol administrator eindigde met exitcode $status en leverde geen bruikbare uitvoer op. De beheerdersaccounts van deze installatie zijn dus niet gecontroleerd, wat juist de kernaanwijzing is bij deze aanval." \
            "remediation=Draai wp user list --role=administrator handmatig op deze site."
        detect_wp_mark_check_complete
        return 0
    fi
    if ! detect_wp_json_objects_to_lines "$admins_file" > "$rows_file" 2>/dev/null; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=admin-list-unparsable" \
            "title=De lijst met beheerders was niet leesbaar" \
            "detail=De JSON-uitvoer van wp user list kon niet ontleed worden. De beheerdersaccounts zijn dus niet gecontroleerd." \
            "remediation=Draai wp user list --role=administrator --format=json handmatig en beoordeel de uitvoer."
        detect_wp_mark_check_complete
        return 0
    fi
    local window_datetime window_number
    if ! window_datetime=$(detect_wp_exposure_window_datetime); then
        window_datetime=''
        window_number=''
        log_warn "WP2SHELL_EXPOSURE_WINDOW_START is niet bruikbaar, beheerders worden alleen tegen de allowlist getoetst"
    else
        window_number=$(detect_wp_datetime_to_number "$window_datetime") || window_number=''
    fi
    detect_wp_reset_item_budget
    local line user_id login email registered registered_number rank_note severity detail title
    while IFS= read -r line || [ -n "$line" ]; do
        if [ -z "$line" ]; then
            continue
        fi
        user_id=$(json_extract_field "$line" ID) || user_id=''
        login=$(json_extract_field "$line" user_login) || login=''
        email=$(json_extract_field "$line" user_email) || email=''
        registered=$(json_extract_field "$line" user_registered) || registered=''
        WP2SHELL_DETECT_WP_ADMIN_TOTAL=$((WP2SHELL_DETECT_WP_ADMIN_TOTAL + 1))
        if is_allowlisted_admin "$login" "$email"; then
            log_debug "Beheerder op de allowlist overgeslagen: $login"
            continue
        fi
        rank_note=$(detect_wp_admin_rank_note "$login" "$email") || rank_note=''
        registered_number=$(detect_wp_datetime_to_number "$registered") || registered_number=''
        local account_is_in_window=0
        if [ -n "$window_number" ] && [ -n "$registered_number" ] && [ "$registered_number" -ge "$window_number" ]; then
            account_is_in_window=1
        fi
        if [ "$account_is_in_window" != "1" ]; then
            if ! detect_wp_consume_item_budget; then
                WP2SHELL_DETECT_WP_ADMIN_TRUNCATED=$((${WP2SHELL_DETECT_WP_ADMIN_TRUNCATED:-0} + 1))
                continue
            fi
        fi
        if [ "$account_is_in_window" = "1" ]; then
            WP2SHELL_DETECT_WP_ADMIN_IN_WINDOW=$((WP2SHELL_DETECT_WP_ADMIN_IN_WINDOW + 1))
            detail="Beheerder $login met e-mailadres $email is aangemaakt op $registered, dat is op of na het begin van het blootstellingsvenster ($window_datetime). Een nieuw beheerdersaccount binnen dat venster is de bekendste vorm van persistentie bij deze aanval."
            if [ -n "$rank_note" ]; then
                detail="$detail Het account past bovendien bij het door leveranciers gerapporteerde naampatroon ($rank_note)."
            else
                detail="$detail Het account past niet bij het gerapporteerde naampatroon, maar dat zegt weinig: een aanvaller past namen triviaal aan."
            fi
            record_finding \
                "site=$site_path" \
                "severity=$SEVERITY_CRITICAL" \
                "confidence=$CONFIDENCE_HIGH" \
                "category=admin-created-in-exposure-window" \
                "title=Beheerdersaccount aangemaakt binnen het blootstellingsvenster" \
                "detail=$detail" \
                "evidence=ID $user_id, login $login, e-mail $email, aangemaakt $registered" \
                "remediation=Controleer bij de klant of dit account van hen is. Is dat niet zo, verwijder het pas in de opschoonstap met --remove-admins en roteer daarna alle wachtwoorden en salts. Deze module verwijdert zelf niets."
            continue
        fi
        severity="$SEVERITY_HIGH"
        title="Beheerdersaccount staat niet op de allowlist"
        detail="Beheerder $login met e-mailadres $email staat niet op de allowlist. Aanmaakdatum: ${registered:-onbekend}."
        if [ -z "$registered_number" ]; then
            detail="$detail De aanmaakdatum is leeg of onleesbaar, wat op een account wijst dat buiten WordPress om in de database is gezet."
        fi
        if [ -n "$rank_note" ]; then
            detail="$detail Het account past bij het door leveranciers gerapporteerde naampatroon ($rank_note)."
        fi
        detail="$detail Dit blijft heuristisch: een legitieme beheerder van de klant komt hier ook in terecht zolang die niet op de allowlist staat."
        record_finding \
            "site=$site_path" \
            "severity=$severity" \
            "confidence=$CONFIDENCE_HEURISTIC" \
            "category=admin-not-allowlisted" \
            "title=$title" \
            "detail=$detail" \
            "evidence=ID $user_id, login $login, e-mail $email, aangemaakt ${registered:-onbekend}" \
            "remediation=Laat de klant dit account bevestigen en zet het daarna op de allowlist in de configuratie."
    done < "$rows_file"
    if [ "$WP2SHELL_DETECT_WP_ADMIN_TOTAL" -eq 0 ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HEURISTIC" \
            "category=admin-none-found" \
            "title=Geen enkele beheerder gevonden" \
            "detail=Deze installatie heeft geen enkel account met de rol administrator. Dat is ongebruikelijk en kan betekenen dat rollen zijn aangepast of dat accounts buiten WordPress om uit de database zijn verwijderd." \
            "remediation=Controleer de tabel usermeta op capabilities-rijen en herstel het beheerdersaccount van de klant."
    fi
    log_info "Beheerders $site_path: totaal $WP2SHELL_DETECT_WP_ADMIN_TOTAL, binnen venster $WP2SHELL_DETECT_WP_ADMIN_IN_WINDOW"
    detect_wp_mark_check_complete
    return 0
}

detect_wp_db_query() {
    local site_path=$1 owner_user=$2 label=$3 sql=$4
    local status
    status=$(detect_wp_capture "$site_path" "$owner_user" "$label" db query "$sql" --skip-column-names)
    if [ "$status" != "0" ]; then
        log_debug "db query $label gaf exitcode $status voor $site_path"
        return 1
    fi
    return 0
}

detect_wp_resolve_table_prefix() {
    local site_path=$1 owner_user=$2 value line
    value=$(wp_run "$owner_user" "$site_path" db prefix 2>/dev/null) || value=''
    value=${value%%$'\n'*}
    value=${value// /}
    if detect_wp_identifier_is_safe "$value"; then
        printf '%s' "$value"
        return 0
    fi
    local config_file
    if config_file=$(detect_wp_config_file "$site_path"); then
        line=$(grep -m1 -E '^[[:space:]]*\$table_prefix[[:space:]]*=' -- "$config_file" 2>/dev/null) || line=''
        if [[ $line =~ \$table_prefix[[:space:]]*=[[:space:]]*[\'\"]([A-Za-z0-9_]+)[\'\"] ]]; then
            printf '%s' "${BASH_REMATCH[1]}"
            return 0
        fi
    fi
    return 1
}

detect_wp_check_autoloaded_options() {
    local site_path=$1 owner_user=$2 prefix=$3
    local marker escaped
    local -a flag_columns=() where_terms=()
    for marker in "${WP2SHELL_DETECT_WP_OPTION_MARKERS[@]}"; do
        if ! detect_wp_sql_pattern_is_safe "$marker"; then
            log_warn "Zoekpatroon niet veilig voor SQL en daarom overgeslagen: $marker"
            continue
        fi
        escaped=$(detect_wp_sql_quote_pattern "$marker")
        flag_columns+=("(option_value LIKE '%$escaped%')")
        where_terms+=("option_value LIKE '%$escaped%'")
    done
    if [ "${#flag_columns[@]}" -eq 0 ]; then
        return 0
    fi
    local columns where_clause sanitized sql
    columns=$(detect_wp_join_with ", " "${flag_columns[@]}")
    where_clause=$(detect_wp_join_with " OR " "${where_terms[@]}")
    sanitized="REPLACE(REPLACE(REPLACE(option_value, CHAR(10), ' '), CHAR(13), ' '), CHAR(9), ' ')"
    sql="SELECT option_name, autoload, LENGTH(option_value), $columns, LEFT($sanitized, 400)"
    sql="$sql FROM \`${prefix}options\` WHERE autoload IN ('yes','on','auto-on','auto')"
    sql="$sql AND ($where_clause) ORDER BY LENGTH(option_value) DESC LIMIT 50"
    if ! detect_wp_db_query "$site_path" "$owner_user" autoload-options "$sql"; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=db-autoload-query-failed" \
            "title=Autoloaded opties konden niet doorzocht worden" \
            "detail=De databasequery op de options-tabel is mislukt. Er is teruggevallen op wp option list, wat op WordPress 6.6 en nieuwer onder-rapporteert omdat alleen de waarden yes en on worden meegenomen en niet auto en auto-on." \
            "remediation=Controleer de rechten van de databasegebruiker en draai de query handmatig."
        detect_wp_check_autoloaded_options_fallback "$site_path" "$owner_user"
        return 0
    fi
    local results_file
    results_file=$(detect_wp_work_file autoload-options.out)
    local line option_name autoload_value length snippet
    local -a fields=()
    local marker_count=${#WP2SHELL_DETECT_WP_OPTION_MARKERS[@]}
    local index flag_index matched
    local -a matched_markers=()
    detect_wp_reset_item_budget
    while IFS= read -r line || [ -n "$line" ]; do
        if [ -z "$line" ]; then
            continue
        fi
        IFS=$'\t' read -r -a fields <<< "$line"
        if [ "${#fields[@]}" -lt 4 ]; then
            continue
        fi
        option_name=${fields[0]}
        autoload_value=${fields[1]}
        length=${fields[2]}
        snippet=${fields[$((${#fields[@]} - 1))]}
        matched_markers=()
        index=0
        for marker in "${WP2SHELL_DETECT_WP_OPTION_MARKERS[@]}"; do
            flag_index=$((3 + index))
            index=$((index + 1))
            if [ "$flag_index" -ge "${#fields[@]}" ]; then
                continue
            fi
            matched=${fields[$flag_index]}
            if [ "$matched" = "1" ]; then
                matched_markers+=("$marker")
            fi
        done
        if [ "${#matched_markers[@]}" -eq 0 ]; then
            continue
        fi
        detect_wp_evaluate_text_signals "$snippet"
        local severity="$WP2SHELL_DETECT_WP_SIGNAL_SEVERITY"
        local confidence="$WP2SHELL_DETECT_WP_SIGNAL_CONFIDENCE"
        if [ "$confidence" != "$CONFIDENCE_HIGH" ]; then
            if [ "${#matched_markers[@]}" -ge 2 ]; then
                severity="$SEVERITY_HIGH"
            else
                severity="$SEVERITY_MEDIUM"
            fi
        fi
        if ! detect_wp_consume_item_budget; then
            continue
        fi
        record_finding \
            "site=$site_path" \
            "severity=$severity" \
            "confidence=$confidence" \
            "category=db-autoloaded-option-code" \
            "title=Autoloaded optie bevat codepatronen" \
            "detail=De optie $option_name wordt bij elke paginaweergave geladen (autoload $autoload_value, $length bytes) en bevat $(detect_wp_join_with ", " "${matched_markers[@]}"). Autoloaded opties zijn een bekende persistentieplek omdat de inhoud bij elke request beschikbaar is. ${WP2SHELL_DETECT_WP_SIGNAL_EVIDENCE:-Beoordeel de inhoud handmatig.}" \
            "evidence=$(detect_wp_shorten "$snippet" 300)" \
            "remediation=Bekijk de volledige waarde met wp option get $option_name en verwijder de optie pas na een databasebackup in de opschoonstap."
    done < "$results_file"
    detect_wp_check_large_autoloaded_options "$site_path" "$owner_user" "$prefix"
    return 0
}

detect_wp_check_autoloaded_options_fallback() {
    local site_path=$1 owner_user=$2
    local options_file rows_file line option_name option_value
    options_file=$(detect_wp_work_file autoload-fallback.out)
    rows_file=$(detect_wp_work_file autoload-fallback-rows.txt)
    if ! wp_run "$owner_user" "$site_path" option list --autoload=on \
        --fields=option_name,option_value --format=json >"$options_file" 2>/dev/null; then
        return 0
    fi
    if ! detect_wp_json_objects_to_lines "$options_file" > "$rows_file" 2>/dev/null; then
        return 0
    fi
    detect_wp_reset_item_budget
    local marker
    local -a matched_markers=()
    while IFS= read -r line || [ -n "$line" ]; do
        if [ -z "$line" ]; then
            continue
        fi
        option_name=$(json_extract_field "$line" option_name) || option_name=''
        option_value=$(json_extract_field "$line" option_value) || option_value=''
        if [ -z "$option_value" ]; then
            continue
        fi
        matched_markers=()
        for marker in "${WP2SHELL_DETECT_WP_OPTION_MARKERS[@]}"; do
            case $option_value in
                *"$marker"*) matched_markers+=("$marker") ;;
            esac
        done
        if [ "${#matched_markers[@]}" -eq 0 ]; then
            continue
        fi
        if ! detect_wp_consume_item_budget; then
            continue
        fi
        detect_wp_evaluate_text_signals "$option_value"
        record_finding \
            "site=$site_path" \
            "severity=$WP2SHELL_DETECT_WP_SIGNAL_SEVERITY" \
            "confidence=$WP2SHELL_DETECT_WP_SIGNAL_CONFIDENCE" \
            "category=db-autoloaded-option-code" \
            "title=Autoloaded optie bevat codepatronen" \
            "detail=De optie $option_name bevat $(detect_wp_join_with ", " "${matched_markers[@]}"). Deze bevinding komt uit de terugvaloptie wp option list, die op WordPress 6.6 en nieuwer niet alle autoloadwaarden meeneemt. Er kunnen dus meer opties zijn die hier niet in staan." \
            "evidence=$(detect_wp_shorten "$option_value" 300)" \
            "remediation=Bekijk de volledige waarde met wp option get $option_name en beoordeel deze handmatig."
    done < "$rows_file"
    return 0
}

detect_wp_check_large_autoloaded_options() {
    local site_path=$1 owner_user=$2 prefix=$3
    local threshold=${WP2SHELL_AUTOLOAD_OPTION_MAX_BYTES:-262144}
    case $threshold in
        ''|*[!0-9]*) threshold=262144 ;;
    esac
    local sql results_file line option_name autoload_value length
    sql="SELECT option_name, autoload, LENGTH(option_value) FROM \`${prefix}options\`"
    sql="$sql WHERE autoload IN ('yes','on','auto-on','auto') ORDER BY LENGTH(option_value) DESC LIMIT 10"
    if ! detect_wp_db_query "$site_path" "$owner_user" autoload-size "$sql"; then
        return 0
    fi
    results_file=$(detect_wp_work_file autoload-size.out)
    local -a oversized=()
    while IFS=$'\t' read -r option_name autoload_value length || [ -n "$option_name" ]; do
        if [ -z "$option_name" ]; then
            continue
        fi
        case $length in
            ''|*[!0-9]*) continue ;;
        esac
        if [ "$length" -gt "$threshold" ]; then
            oversized+=("$option_name ($length bytes, autoload $autoload_value)")
        fi
    done < "$results_file"
    if [ "${#oversized[@]}" -eq 0 ]; then
        return 0
    fi
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_LOW" \
        "confidence=$CONFIDENCE_HEURISTIC" \
        "category=db-autoloaded-option-oversized" \
        "title=Ongewoon grote autoloaded opties" \
        "detail=Deze opties worden bij elke paginaweergave geladen en zijn groter dan $threshold bytes. Dat is meestal een prestatieprobleem van een plugin, maar een ongewoon grote autoloaded optie is ook een plek waar een payload verstopt kan worden." \
        "evidence=$(detect_wp_shorten "$(detect_wp_join_with "; " "${oversized[@]}")" 400)" \
        "remediation=Bekijk de inhoud van deze opties handmatig met wp option get."
    return 0
}

detect_wp_check_site_urls() {
    local site_path=$1 owner_user=$2 prefix=$3 expected_domain=$4
    local sanitized sql results_file line option_name option_value
    local siteurl='' home=''
    sanitized="REPLACE(REPLACE(REPLACE(option_value, CHAR(10), ' '), CHAR(13), ' '), CHAR(9), ' ')"
    sql="SELECT option_name, LEFT($sanitized, 300) FROM \`${prefix}options\` WHERE option_name IN ('siteurl','home')"
    if ! detect_wp_db_query "$site_path" "$owner_user" site-urls "$sql"; then
        return 0
    fi
    results_file=$(detect_wp_work_file site-urls.out)
    while IFS=$'\t' read -r option_name option_value || [ -n "$option_name" ]; do
        case $option_name in
            siteurl) siteurl=$option_value ;;
            home) home=$option_value ;;
        esac
    done < "$results_file"
    if [ -z "$siteurl" ] && [ -z "$home" ]; then
        return 0
    fi
    local siteurl_host home_host
    siteurl_host=$(detect_wp_url_host "$siteurl")
    home_host=$(detect_wp_url_host "$home")
    if [ -z "$expected_domain" ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_INFO" \
            "confidence=$CONFIDENCE_HEURISTIC" \
            "category=db-siteurl-unverified" \
            "title=Adres van de site niet te toetsen zonder verwacht domein" \
            "detail=De opties siteurl ($siteurl) en home ($home) konden niet vergeleken worden met een verwacht domein, omdat het domein niet uit het pad van de installatie af te leiden is." \
            "remediation=Controleer handmatig of deze adressen kloppen met het domein van de klant."
        return 0
    fi
    local -a mismatched=()
    if [ -n "$siteurl_host" ] && ! detect_wp_host_matches_domain "$siteurl_host" "$expected_domain"; then
        mismatched+=("siteurl wijst naar $siteurl_host")
    fi
    if [ -n "$home_host" ] && ! detect_wp_host_matches_domain "$home_host" "$expected_domain"; then
        mismatched+=("home wijst naar $home_host")
    fi
    if [ "${#mismatched[@]}" -gt 0 ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_CRITICAL" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=db-siteurl-unexpected" \
            "title=Het adres van de site wijst naar een onverwacht domein" \
            "detail=Op basis van het pad hoort deze installatie bij $expected_domain, maar $(detect_wp_join_with " en " "${mismatched[@]}"). Een gewijzigde siteurl of home stuurt bezoekers en beheerders naar een door de aanvaller gekozen adres en is een klassieke overname. Let op: een bewust ingestelde alias of een domein dat verhuisd is geeft hier ook een melding." \
            "evidence=siteurl $siteurl, home $home, verwacht domein $expected_domain" \
            "remediation=Bevestig bij de klant welk adres hoort te staan en herstel siteurl en home pas in de opschoonstap, na een databasebackup."
        return 0
    fi
    if [ -n "$siteurl_host" ] && [ -n "$home_host" ] && [ "$siteurl_host" != "$home_host" ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HEURISTIC" \
            "category=db-siteurl-mismatch" \
            "title=siteurl en home verschillen van elkaar" \
            "detail=De optie siteurl wijst naar $siteurl_host en home naar $home_host. Dat kan een bewuste inrichting zijn waarbij WordPress in een submap staat, maar het is ook een bekende manier om bezoekers weg te leiden." \
            "evidence=siteurl $siteurl, home $home" \
            "remediation=Controleer bij de klant of deze inrichting klopt."
    fi
    return 0
}

detect_wp_check_active_plugins() {
    local site_path=$1 owner_user=$2
    local plugins_dir raw_file entries_file line entry directory
    WP2SHELL_DETECT_WP_ACTIVE_PLUGINS_FILE=""
    plugins_dir=$(detect_wp_plugins_directory "$site_path" "$owner_user") || plugins_dir=''
    if [ -z "$plugins_dir" ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=active-plugins-directory-unknown" \
            "title=De pluginmap kon niet bepaald worden" \
            "detail=Zonder de pluginmap kan niet gecontroleerd worden of de actieve plugins ook echt op schijf staan. Een plugin die actief is maar ontbreekt, of andersom, is een bekende aanwijzing voor manipulatie. Dit onderdeel is dus niet gecontroleerd." \
            "remediation=Controleer of wp plugin path werkt op deze site en of wp-content/plugins bestaat."
        return 1
    fi
    raw_file=$(detect_wp_work_file active-plugins.json)
    entries_file=$(detect_wp_work_file active-plugins.txt)
    if ! wp_run "$owner_user" "$site_path" option get active_plugins --format=json \
        >"$raw_file" 2>/dev/null; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=db-active-plugins-unavailable" \
            "title=De lijst met actieve plugins kon niet gelezen worden" \
            "detail=De optie active_plugins kon niet opgehaald worden, dus er is niet gecontroleerd of alle actieve plugins ook echt op schijf staan." \
            "remediation=Draai wp option get active_plugins handmatig op deze site."
        detect_wp_mark_check_complete
        return 0
    fi
    if ! detect_wp_json_values_to_lines "$raw_file" > "$entries_file" 2>/dev/null; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=db-active-plugins-unparsable" \
            "title=De lijst met actieve plugins was niet te lezen" \
            "detail=De waarde van active_plugins leverde uitvoer op die niet te verwerken was. Daardoor is niet gecontroleerd of de actieve plugins overeenkomen met wat er op schijf staat, en dat is juist een van de plekken waar manipulatie zichtbaar wordt." \
            "remediation=Draai wp option get active_plugins handmatig op deze site en bekijk waarom de uitvoer afwijkt."
        return 1
    fi
    WP2SHELL_DETECT_WP_ACTIVE_PLUGINS_FILE="$entries_file"
    detect_wp_reset_item_budget
    while IFS= read -r entry || [ -n "$entry" ]; do
        if [ -z "$entry" ]; then
            continue
        fi
        case $entry in
            *..*) ;;
        esac
        if [ -f "$plugins_dir/$entry" ]; then
            continue
        fi
        if ! detect_wp_consume_item_budget; then
            continue
        fi
        directory=${entry%%/*}
        if [ "$directory" != "$entry" ] && [ -d "$plugins_dir/$directory" ]; then
            record_finding \
                "site=$site_path" \
                "severity=$SEVERITY_HIGH" \
                "confidence=$CONFIDENCE_HEURISTIC" \
                "category=db-active-plugin-name-mismatch" \
                "title=Actieve plugin draait onder een andere bestandsnaam dan op schijf" \
                "detail=In active_plugins staat $entry, maar dat bestand bestaat niet terwijl de map $directory er wel is. Dat gebeurt bij een half afgebroken update, maar ook wanneer een hoofdbestand hernoemd of vervangen is." \
                "file=$plugins_dir/$entry" \
                "evidence=active_plugins bevat $entry" \
                "remediation=Vergelijk de inhoud van de map $directory met een schone kopie van de plugin."
            continue
        fi
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_HIGH" \
            "confidence=$CONFIDENCE_HEURISTIC" \
            "category=db-active-plugin-missing" \
            "title=Actieve plugin bestaat niet op schijf" \
            "detail=In active_plugins staat $entry, maar er staat niets op die plek in de pluginmap. WordPress zet zulke regels normaal zelf uit, dus een blijvende verwijzing wijst op een plugin die buiten WordPress om is neergezet en weer verwijderd, of op een aangepaste database." \
            "file=$plugins_dir/$entry" \
            "evidence=active_plugins bevat $entry" \
            "remediation=Controleer de tabel options op de rij active_plugins en vergelijk met een backup van voor 17 juli 2026."
    done < "$entries_file"
    detect_wp_mark_check_complete
    return 0
}

detect_wp_check_bridge_posts() {
    local site_path=$1 owner_user=$2 prefix=$3
    local sanitized sql results_file max_post_id=0
    sql="SELECT COALESCE(MAX(ID), 0) FROM \`${prefix}posts\`"
    if detect_wp_db_query "$site_path" "$owner_user" max-post-id "$sql"; then
        results_file=$(detect_wp_work_file max-post-id.out)
        read -r max_post_id < "$results_file" || max_post_id=0
        case $max_post_id in
            ''|*[!0-9]*) max_post_id=0 ;;
        esac
    fi
    sanitized="REPLACE(REPLACE(REPLACE(post_content, CHAR(10), ' '), CHAR(13), ' '), CHAR(9), ' ')"
    sql="SELECT ID, post_type, post_status, post_parent, post_date_gmt, post_modified_gmt, LEFT($sanitized, 400)"
    sql="$sql FROM \`${prefix}posts\` WHERE post_type IN ('customize_changeset','oembed_cache')"
    sql="$sql ORDER BY post_modified_gmt DESC LIMIT 100"
    if ! detect_wp_db_query "$site_path" "$owner_user" bridge-posts "$sql"; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=db-bridge-posts-query-failed" \
            "title=Changesets en oembed-cache konden niet gecontroleerd worden" \
            "detail=De query op de posts-tabel is mislukt. De gedocumenteerde brug van de SQL-injectie naar een beheerdersaccount loopt juist via customize_changeset en oembed_cache, dus deze installatie is op dat punt niet gecontroleerd." \
            "remediation=Draai de query handmatig of controleer de rechten van de databasegebruiker."
        return 0
    fi
    results_file=$(detect_wp_work_file bridge-posts.out)
    local window_datetime window_number
    window_datetime=$(detect_wp_exposure_window_datetime) || window_datetime=''
    window_number=''
    if [ -n "$window_datetime" ]; then
        window_number=$(detect_wp_datetime_to_number "$window_datetime") || window_number=''
    fi
    local post_id post_type post_status post_parent post_date post_modified snippet
    local modified_number changeset_total=0 oembed_total=0
    local -a in_window=() impossible_parent=()
    detect_wp_reset_item_budget
    while IFS=$'\t' read -r post_id post_type post_status post_parent post_date post_modified snippet \
        || [ -n "$post_id" ]; do
        if [ -z "$post_id" ]; then
            continue
        fi
        case $post_type in
            customize_changeset) changeset_total=$((changeset_total + 1)) ;;
            oembed_cache) oembed_total=$((oembed_total + 1)) ;;
        esac
        modified_number=$(detect_wp_datetime_to_number "$post_modified") || modified_number=''
        if [ -n "$window_number" ] && [ -n "$modified_number" ] && [ "$modified_number" -ge "$window_number" ]; then
            in_window+=("$post_type $post_id ($post_status, gewijzigd $post_modified)")
        fi
        case $post_parent in
            ''|*[!0-9]*) ;;
            *)
                if [ "$max_post_id" -gt 0 ] && [ "$post_parent" -gt "$max_post_id" ]; then
                    impossible_parent+=("$post_type $post_id verwijst naar bovenliggende post $post_parent")
                fi
                ;;
        esac
        if [ -n "$snippet" ]; then
            detect_wp_evaluate_text_signals "$snippet"
            case $snippet in
                *'<?php'*|*'<?='*)
                    if [ "$WP2SHELL_DETECT_WP_SIGNAL_CONFIDENCE" != "$CONFIDENCE_HIGH" ]; then
                        WP2SHELL_DETECT_WP_SIGNAL_SEVERITY="$SEVERITY_HIGH"
                        WP2SHELL_DETECT_WP_SIGNAL_EVIDENCE="PHP-code in een rij die alleen instellingen of externe HTML hoort te bevatten."
                    fi
                    ;;
            esac
            if [ "$WP2SHELL_DETECT_WP_SIGNAL_SEVERITY" != "$SEVERITY_LOW" ]; then
                if detect_wp_consume_item_budget; then
                    record_finding \
                        "site=$site_path" \
                        "severity=$WP2SHELL_DETECT_WP_SIGNAL_SEVERITY" \
                        "confidence=$WP2SHELL_DETECT_WP_SIGNAL_CONFIDENCE" \
                        "category=db-bridge-post-code" \
                        "title=Codepatronen in een changeset of oembed-cache" \
                        "detail=De rij $post_type met ID $post_id bevat patronen die daar niet horen. Een oembed-cache bevat normaal alleen HTML van een externe aanbieder en een changeset alleen instellingen van de customizer. ${WP2SHELL_DETECT_WP_SIGNAL_EVIDENCE:-Beoordeel de inhoud handmatig.}" \
                        "evidence=$(detect_wp_shorten "$snippet" 300)" \
                        "remediation=Bekijk de volledige rij in de posts-tabel en bewaar deze als bewijs voordat er iets verwijderd wordt."
                fi
            fi
        fi
    done < "$results_file"
    if [ "${#in_window[@]}" -gt 0 ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HEURISTIC" \
            "category=db-bridge-posts-in-window" \
            "title=Changesets of oembed-cache gewijzigd binnen het blootstellingsvenster" \
            "detail=Er zijn ${#in_window[@]} rijen van het type customize_changeset of oembed_cache die op of na $window_datetime zijn gewijzigd. Via precies deze twee posttypes schrijft de gedocumenteerde brug van de SQL-injectie naar wp_options. Op een actief beheerde site zijn deze rijen ook volkomen normaal, dus dit is een aanwijzing en geen bewijs." \
            "evidence=$(detect_wp_shorten "$(detect_wp_join_with "; " "${in_window[@]}")" 400)" \
            "remediation=Vergelijk deze rijen met het beheerlogboek van de klant en met de aanmaakdatum van eventuele nieuwe beheerders."
    fi
    if [ "${#impossible_parent[@]}" -gt 0 ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_HIGH" \
            "confidence=$CONFIDENCE_HEURISTIC" \
            "category=db-bridge-post-parent-anomaly" \
            "title=Changeset verwijst naar een niet-bestaande bovenliggende post" \
            "detail=Deze rijen verwijzen naar een bovenliggende post met een ID dat hoger ligt dan het hoogste bestaande post-ID ($max_post_id). Dat kan niet ontstaan via de normale weg in WordPress en past bij het gedocumenteerde patroon waarbij via de SQL-injectie rijen met een zeer hoog bovenliggend ID worden weggeschreven." \
            "evidence=$(detect_wp_shorten "$(detect_wp_join_with "; " "${impossible_parent[@]}")" 400)" \
            "remediation=Bewaar deze rijen als bewijs en controleer alle beheerdersaccounts en autoloaded opties op dezelfde periode."
    fi
    log_debug "Bridge-posts $site_path: changesets $changeset_total, oembed $oembed_total"
    return 0
}

detect_wp_check_oembed_options() {
    local site_path=$1 owner_user=$2 prefix=$3
    local sql results_file line option_name snippet
    local sanitized
    sanitized="REPLACE(REPLACE(REPLACE(option_value, CHAR(10), ' '), CHAR(13), ' '), CHAR(9), ' ')"
    sql="SELECT option_name, LEFT($sanitized, 300) FROM \`${prefix}options\` WHERE option_name LIKE '%oembed%' LIMIT 25"
    if ! detect_wp_db_query "$site_path" "$owner_user" oembed-options "$sql"; then
        return 0
    fi
    results_file=$(detect_wp_work_file oembed-options.out)
    local -a rows=()
    while IFS=$'\t' read -r option_name snippet || [ -n "$option_name" ]; do
        if [ -z "$option_name" ]; then
            continue
        fi
        rows+=("$option_name")
        detect_wp_evaluate_text_signals "$snippet"
        if [ "$WP2SHELL_DETECT_WP_SIGNAL_SEVERITY" != "$SEVERITY_LOW" ]; then
            record_finding \
                "site=$site_path" \
                "severity=$WP2SHELL_DETECT_WP_SIGNAL_SEVERITY" \
                "confidence=$WP2SHELL_DETECT_WP_SIGNAL_CONFIDENCE" \
                "category=db-oembed-option-code" \
                "title=Codepatronen in een oembed-optie" \
                "detail=De optie $option_name bevat patronen die in een oembed-cache niet horen voor te komen. ${WP2SHELL_DETECT_WP_SIGNAL_EVIDENCE:-Beoordeel de inhoud handmatig.}" \
                "evidence=$(detect_wp_shorten "$snippet" 300)" \
                "remediation=Bekijk de volledige waarde met wp option get $option_name en bewaar deze als bewijs."
        fi
    done < "$results_file"
    if [ "${#rows[@]}" -eq 0 ]; then
        return 0
    fi
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_LOW" \
        "confidence=$CONFIDENCE_HEURISTIC" \
        "category=db-oembed-options-present" \
        "title=oembed-rijen in de options-tabel" \
        "detail=WordPress bewaart de oembed-cache normaal in postmeta en niet in de options-tabel. Er staan hier ${#rows[@]} rijen met oembed in de naam. Sommige plugins doen dit legitiem, dus dit is alleen een aanknopingspunt voor handmatige review." \
        "evidence=$(detect_wp_shorten "$(detect_wp_join_with ", " "${rows[@]}")" 400)" \
        "remediation=Controleer of een van de geinstalleerde plugins deze opties aanmaakt."
    return 0
}

detect_wp_check_user_gaps() {
    local site_path=$1 owner_user=$2 prefix=$3
    local sql results_file total minimum maximum gap=0
    sql="SELECT COUNT(*), COALESCE(MIN(ID), 0), COALESCE(MAX(ID), 0) FROM \`${prefix}users\`"
    if ! detect_wp_db_query "$site_path" "$owner_user" user-range "$sql"; then
        return 0
    fi
    results_file=$(detect_wp_work_file user-range.out)
    IFS=$'\t' read -r total minimum maximum < "$results_file" || return 0
    case $total in
        ''|*[!0-9]*) return 0 ;;
    esac
    case $minimum in
        ''|*[!0-9]*) return 0 ;;
    esac
    case $maximum in
        ''|*[!0-9]*) return 0 ;;
    esac
    if [ "$total" -gt 0 ] && [ "$maximum" -ge "$minimum" ]; then
        gap=$((maximum - minimum + 1 - total))
    fi
    local orphan_total=0 orphan_admins=''
    sql="SELECT COUNT(DISTINCT m.user_id) FROM \`${prefix}usermeta\` m"
    sql="$sql LEFT JOIN \`${prefix}users\` u ON u.ID = m.user_id WHERE u.ID IS NULL"
    if detect_wp_db_query "$site_path" "$owner_user" orphan-usermeta "$sql"; then
        results_file=$(detect_wp_work_file orphan-usermeta.out)
        read -r orphan_total < "$results_file" || orphan_total=0
        case $orphan_total in
            ''|*[!0-9]*) orphan_total=0 ;;
        esac
    fi
    local -a orphan_admin_ids=()
    sql="SELECT DISTINCT m.user_id FROM \`${prefix}usermeta\` m"
    sql="$sql LEFT JOIN \`${prefix}users\` u ON u.ID = m.user_id"
    sql="$sql WHERE u.ID IS NULL AND m.meta_key LIKE '%capabilities' AND m.meta_value LIKE '%administrator%' LIMIT 25"
    if detect_wp_db_query "$site_path" "$owner_user" orphan-admins "$sql"; then
        results_file=$(detect_wp_work_file orphan-admins.out)
        local orphan_id
        while IFS= read -r orphan_id || [ -n "$orphan_id" ]; do
            case $orphan_id in
                ''|*[!0-9]*) continue ;;
            esac
            orphan_admin_ids+=("$orphan_id")
        done < "$results_file"
    fi
    if [ "${#orphan_admin_ids[@]}" -gt 0 ]; then
        orphan_admins=$(detect_wp_join_with ", " "${orphan_admin_ids[@]}")
        local severity confidence detail
        if [ "$gap" -gt 0 ]; then
            severity="$SEVERITY_HIGH"
            confidence="$CONFIDENCE_HIGH"
            detail="Er staan usermeta-rijen met beheerdersrechten voor gebruikers die niet meer bestaan (ID's: $orphan_admins), en tegelijk zitten er $gap gaten in de reeks gebruikers-ID's. Twee onafhankelijke structurele signalen wijzen hier dezelfde kant op: een beheerdersaccount is buiten WordPress om uit de database verwijderd, want wp_delete_user ruimt de usermeta altijd mee op."
        else
            severity="$SEVERITY_MEDIUM"
            confidence="$CONFIDENCE_HEURISTIC"
            detail="Er staan usermeta-rijen met beheerdersrechten voor gebruikers die niet meer bestaan (ID's: $orphan_admins). Dat kan wijzen op een verwijderd beheerdersaccount, maar een oude migratie of een plugin die rijen achterlaat geeft hetzelfde beeld."
        fi
        record_finding \
            "site=$site_path" \
            "severity=$severity" \
            "confidence=$confidence" \
            "category=db-orphaned-admin-usermeta" \
            "title=Verweesde beheerdersrechten in usermeta" \
            "detail=$detail" \
            "evidence=Verweesde gebruikers-ID's met beheerdersrechten: $orphan_admins, totaal verweesde gebruikers $orphan_total, gaten in de ID-reeks $gap" \
            "remediation=Zoek in backups op welk account bij deze ID's hoorde en controleer de logs rond het tijdstip waarop dat account verdween."
        return 0
    fi
    if [ "$orphan_total" -gt 0 ] || [ "$gap" -gt 0 ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HEURISTIC" \
            "category=db-user-gaps" \
            "title=Gaten in de gebruikersreeks of verweesde usermeta" \
            "detail=De gebruikers-ID's lopen van $minimum tot $maximum met $total accounts, dus er zijn $gap ontbrekende ID's. Daarnaast zijn er $orphan_total gebruikers met usermeta zonder bijbehorend account. Verwijderde accounts zijn heel gewoon, maar bij deze aanval hoort het opruimen van een tijdelijk beheerdersaccount ook precies dit spoor achter te laten." \
            "remediation=Vergelijk de gebruikerslijst met een backup van voor 17 juli 2026."
    fi
    return 0
}

detect_wp_database_persistence() {
    local site_path=$1 owner_user=$2 expected_domain=$3
    WP2SHELL_DETECT_WP_DB_STATUS='niet uitgevoerd'
    local prefix
    if ! detect_wp_db_query "$site_path" "$owner_user" db-probe "SELECT 1"; then
        WP2SHELL_DETECT_WP_DB_STATUS='niet beschikbaar'
        local error_line=''
        error_line=$(detect_wp_first_error_line "$(detect_wp_work_file db-probe.err)") || error_line=''
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=db-query-unavailable" \
            "title=De databasecontroles konden niet uitgevoerd worden" \
            "detail=wp db query werkt niet op deze installatie. Dat kan komen door ontbrekende rechten van de databasegebruiker, een ontbrekende mysql-client of een geblokkeerde proc_open. De databasecontroles zijn juist het belangrijkste bewijsmateriaal bij deze aanval, omdat een netjes uitgevoerde inbraak nauwelijks sporen in de webserverlogs achterlaat. Deze installatie mag daarom niet als schoon gelezen worden." \
            "evidence=$error_line" \
            "remediation=Controleer de databasegegevens in wp-config.php, de rechten van de databasegebruiker en de beschikbaarheid van de mysql-client."
        detect_wp_mark_check_complete
        return 0
    fi
    if ! prefix=$(detect_wp_resolve_table_prefix "$site_path" "$owner_user"); then
        WP2SHELL_DETECT_WP_DB_STATUS='tabelprefix onbekend'
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=db-prefix-unknown" \
            "title=De tabelprefix kon niet veilig bepaald worden" \
            "detail=De tabelprefix van deze installatie is niet vast te stellen, of bevat tekens die niet in een tabelnaam thuishoren. Er worden geen queries uitgevoerd met een prefix die niet gevalideerd is, dus de databasecontroles zijn overgeslagen." \
            "remediation=Controleer de regel met table_prefix in wp-config.php."
        detect_wp_mark_check_complete
        return 0
    fi
    WP2SHELL_DETECT_WP_TABLE_PREFIX="$prefix"
    WP2SHELL_DETECT_WP_DB_STATUS="uitgevoerd met prefix $prefix"
    detect_wp_check_autoloaded_options "$site_path" "$owner_user" "$prefix"
    detect_wp_check_site_urls "$site_path" "$owner_user" "$prefix" "$expected_domain"
    detect_wp_check_bridge_posts "$site_path" "$owner_user" "$prefix"
    detect_wp_check_oembed_options "$site_path" "$owner_user" "$prefix"
    detect_wp_check_user_gaps "$site_path" "$owner_user" "$prefix"
    detect_wp_mark_check_complete
    return 0
}

detect_wp_hook_is_known() {
    local hook=$1 known
    if [ "${#WP2SHELL_KNOWN_CRON_HOOKS[@]}" -eq 0 ]; then
        return 1
    fi
    for known in "${WP2SHELL_KNOWN_CRON_HOOKS[@]}"; do
        if [ "$known" = "$hook" ]; then
            return 0
        fi
    done
    return 1
}

detect_wp_hook_looks_random() {
    local hook=$1
    case ${hook,,} in
        *eval*|*base64*|*shell*|*exec*|*backdoor*) return 0 ;;
    esac
    if [[ $hook =~ ^[0-9a-f]{16,}$ ]]; then
        return 0
    fi
    if [[ $hook =~ ^[A-Za-z0-9+/]{24,}={0,2}$ ]]; then
        return 0
    fi
    return 1
}

detect_wp_scheduled_tasks() {
    local site_path=$1 owner_user=$2
    local cron_file rows_file status line hook next_run recurrence
    cron_file=$(detect_wp_work_file cron.out)
    rows_file=$(detect_wp_work_file cron-rows.txt)
    status=$(detect_wp_capture "$site_path" "$owner_user" cron \
        cron event list --fields=hook,next_run_gmt,recurrence --format=json)
    if [ "$status" != "0" ] || [ ! -s "$cron_file" ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=cron-list-unavailable" \
            "title=De geplande taken konden niet opgehaald worden" \
            "detail=wp cron event list eindigde met exitcode $status en leverde geen bruikbare uitvoer op. Geplande taken zijn een gangbare plek voor persistentie, dus dit onderdeel is niet gecontroleerd." \
            "remediation=Draai wp cron event list handmatig op deze site."
        detect_wp_mark_check_complete
        return 0
    fi
    if ! detect_wp_json_objects_to_lines "$cron_file" > "$rows_file" 2>/dev/null; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=cron-list-unparsable" \
            "title=De lijst met geplande taken was niet te lezen" \
            "detail=wp cron event list leverde uitvoer op die niet als JSON te verwerken was. Geplande taken zijn een gangbare plek voor persistentie, dus dit onderdeel is niet gecontroleerd en deze installatie mag op dit punt niet als schoon gelden." \
            "remediation=Draai wp cron event list handmatig op deze site en bekijk waarom de uitvoer afwijkt."
        return 1
    fi
    local -a unknown_hooks=() random_hooks=()
    local -A seen_hooks=()
    while IFS= read -r line || [ -n "$line" ]; do
        if [ -z "$line" ]; then
            continue
        fi
        hook=$(json_extract_field "$line" hook) || hook=''
        next_run=$(json_extract_field "$line" next_run_gmt) || next_run=''
        recurrence=$(json_extract_field "$line" recurrence) || recurrence=''
        if [ -z "$hook" ]; then
            continue
        fi
        if detect_wp_hook_is_known "$hook"; then
            continue
        fi
        if [ -n "${seen_hooks[$hook]:-}" ]; then
            continue
        fi
        seen_hooks[$hook]=1
        unknown_hooks+=("$hook (volgende run $next_run, herhaling ${recurrence:-eenmalig})")
        if detect_wp_hook_looks_random "$hook"; then
            random_hooks+=("$hook")
        fi
    done < "$rows_file"
    if [ "${#random_hooks[@]}" -gt 0 ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HEURISTIC" \
            "category=cron-hook-suspicious-name" \
            "title=Geplande taak met een opvallende naam" \
            "detail=Deze hooknamen zien eruit als willekeurige tekens of bevatten een woord dat naar code-uitvoering verwijst. Voor wp2shell zijn geen hooknamen gepubliceerd, dus dit is een vormsignaal en geen bevestigde indicator." \
            "evidence=$(detect_wp_shorten "$(detect_wp_join_with ", " "${random_hooks[@]}")" 400)" \
            "remediation=Zoek de hooknaam terug in de plugincode. Wordt de naam nergens geregistreerd, dan hoort de taak daar niet."
    fi
    if [ "${#unknown_hooks[@]}" -gt 0 ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HEURISTIC" \
            "category=cron-hook-unrecognised" \
            "title=Geplande taken die niet in de basislijst staan" \
            "detail=Er staan ${#unknown_hooks[@]} geplande taken ingepland waarvan de hook niet in de basislijst van WordPress-core staat. Vrijwel elke plugin voegt eigen taken toe, dus dit is normaal gedrag dat alleen zin heeft als vergelijking met een eerdere basismeting van dezelfde site." \
            "evidence=$(detect_wp_shorten "$(detect_wp_join_with "; " "${unknown_hooks[@]}")" 600)" \
            "remediation=Vergelijk deze lijst met een eerdere meting van dezelfde site en zoek per onbekende hook op welke plugin die registreert."
    fi
    detect_wp_mark_check_complete
    return 0
}

detect_wp_config_file() {
    local site_path=$1 candidate parent
    candidate="$site_path/wp-config.php"
    if [ -f "$candidate" ]; then
        printf '%s' "$candidate"
        return 0
    fi
    parent=$(dirname -- "$site_path")
    candidate="$parent/wp-config.php"
    if [ -f "$candidate" ] && [ ! -f "$parent/wp-settings.php" ]; then
        if path_is_within "$candidate" "$parent"; then
            printf '%s' "$candidate"
            return 0
        fi
        log_warn "wp-config.php buiten de installatie wijst via een symlink naar elders, wordt niet gelezen"
    fi
    return 1
}

detect_wp_config_constant_value() {
    local config_file=$1 constant=$2 line trimmed value pattern
    line=$(grep -m1 -E "define[[:space:]]*\([[:space:]]*['\"]${constant}['\"]" -- "$config_file" 2>/dev/null) || return 1
    trimmed=${line#"${line%%[![:space:]]*}"}
    case $trimmed in
        '//'*|'#'*|'*'*|'/*'*) return 1 ;;
    esac
    pattern="[\"']${constant}[\"'][[:space:]]*,[[:space:]]*([^),;]*)"
    if [[ $line =~ $pattern ]]; then
        value=${BASH_REMATCH[1]}
        value=${value#"${value%%[![:space:]]*}"}
        value=${value%"${value##*[![:space:]]}"}
        value=${value//\'/}
        value=${value//\"/}
        printf '%s' "${value,,}"
        return 0
    fi
    return 1
}

detect_wp_auto_update_posture() {
    local site_path=$1
    local config_file value
    local -a blocking=()
    if ! config_file=$(detect_wp_config_file "$site_path"); then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=wp-config-unreadable" \
            "title=wp-config.php is niet gevonden of niet leesbaar" \
            "detail=Zonder wp-config.php is niet vast te stellen of automatische updates geblokkeerd zijn. Juist de installaties die automatische updates uitzetten stonden het langst bloot aan dit lek." \
            "remediation=Controleer waar wp-config.php staat en of de scan die mag lezen."
        detect_wp_mark_check_complete
        return 0
    fi
    if value=$(detect_wp_config_constant_value "$config_file" AUTOMATIC_UPDATER_DISABLED); then
        case $value in
            true|1) blocking+=("AUTOMATIC_UPDATER_DISABLED op $value") ;;
        esac
    fi
    if value=$(detect_wp_config_constant_value "$config_file" DISALLOW_FILE_MODS); then
        case $value in
            true|1) blocking+=("DISALLOW_FILE_MODS op $value") ;;
        esac
    fi
    if value=$(detect_wp_config_constant_value "$config_file" WP_AUTO_UPDATE_CORE); then
        case $value in
            false|0) blocking+=("WP_AUTO_UPDATE_CORE op $value") ;;
        esac
    fi
    if [ "${#blocking[@]}" -eq 0 ]; then
        detect_wp_mark_check_complete
        return 0
    fi
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_HIGH" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=auto-update-blocked" \
        "title=Automatische updates zijn uitgezet in wp-config.php" \
        "detail=In wp-config.php staat $(detect_wp_join_with " en " "${blocking[@]}"). Deze installatie heeft de securityrelease dus niet vanzelf binnengekregen en stond daardoor het langst bloot aan wp2shell. Deze groep hoort als eerste getriageerd te worden, ook wanneer de versie inmiddels bijgewerkt is: gepatcht is niet hetzelfde als schoon." \
        "file=$config_file" \
        "evidence=$(detect_wp_join_with "; " "${blocking[@]}")" \
        "remediation=Werk deze site met voorrang bij en zet daarna automatische updates voor kleine versies weer aan, in overleg met de klant."
    detect_wp_mark_check_complete
    return 0
}

detect_wp_object_cache_context() {
    local site_path=$1 owner_user=$2
    local content_dir drop_in size digest ioc_label backend='onbekend'
    local -a implemented=()
    local litespeed_note=''
    if [ -n "$WP2SHELL_DETECT_WP_ACTIVE_PLUGINS_FILE" ] && [ -s "$WP2SHELL_DETECT_WP_ACTIVE_PLUGINS_FILE" ]; then
        if grep -qi 'litespeed-cache' -- "$WP2SHELL_DETECT_WP_ACTIVE_PLUGINS_FILE" 2>/dev/null; then
            litespeed_note=" LiteSpeed Cache is actief, maar de paginacache daarvan is geen persistente object cache en telt hier niet mee."
        fi
    fi
    if ! content_dir=$(detect_wp_content_directory "$site_path" "$owner_user"); then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=content-directory-unknown" \
            "title=De wp-content map kon niet bepaald worden" \
            "detail=Zonder wp-content kan de object cache drop-in niet beoordeeld worden. Dat bestand is een bekende plek voor persistentie, dus dit onderdeel is niet gecontroleerd." \
            "remediation=Controleer of wp-content bestaat en leesbaar is voor de scan."
        return 1
    fi
    drop_in="$content_dir/object-cache.php"
    if [ ! -f "$drop_in" ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_INFO" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=object-cache-absent" \
            "title=Geen persistente object cache aanwezig" \
            "detail=Er staat geen object-cache.php in wp-content, dus deze installatie heeft geen persistente object cache. Dit is uitsluitend context.$litespeed_note Het maakt de site niet veilig en neemt geen van beide kwetsbaarheden weg: de stap naar code-uitvoering in deze keten heeft juist geen persistente object cache nodig, en de SQL-injectie werkt hoe dan ook. Er zijn gehashte inloggegevens buitgemaakt voordat de details van de code-uitvoering openbaar waren." \
            "remediation=Behandel dit niet als maatregel. Bijwerken naar een gepatchte versie is de enige oplossing."
        detect_wp_mark_check_complete
        return 0
    fi
    size=$(file_size_bytes "$drop_in") || size=0
    digest=$(file_sha1 "$drop_in") || digest=''
    ioc_label=$(detect_wp_file_ioc_label "$drop_in") || ioc_label=''
    if [ -n "$ioc_label" ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_CRITICAL" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=object-cache-dropin-ioc" \
            "title=De object-cache drop-in komt overeen met een bekende IOC-hash" \
            "detail=Het bestand wp-content/object-cache.php heeft een hash die overeenkomt met een gepubliceerde indicator ($ioc_label). Een drop-in wordt door WordPress bij elke request geladen, nog voor de plugins, en is daarmee een zeer effectieve achterdeur." \
            "file=$drop_in" \
            "sha1=$digest" \
            "remediation=Behandel deze site als gecompromitteerd. Plaats het bestand in de opschoonstap in quarantaine en roteer alle inloggegevens en salts."
        detect_wp_mark_check_complete
        return 0
    fi
    local max_bytes=${WP2SHELL_HEURISTIC_MAX_FILE_BYTES:-5242880}
    case $size in
        ''|*[!0-9]*) size=0 ;;
    esac
    if [ "$size" -gt "$max_bytes" ] || ! grep -qI . -- "$drop_in" 2>/dev/null; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HEURISTIC" \
            "category=object-cache-dropin-unreadable" \
            "title=De object-cache drop-in kon niet beoordeeld worden" \
            "detail=Het bestand wp-content/object-cache.php is $size bytes groot of niet als tekst te lezen, dus de inhoud is niet gecontroleerd. Een drop-in wordt bij elke request geladen en hoort daarom altijd handmatig beoordeeld te worden." \
            "file=$drop_in" \
            "sha1=$digest" \
            "remediation=Bekijk dit bestand handmatig."
        detect_wp_mark_check_complete
        return 0
    fi
    local function_name
    for function_name in wp_cache_get wp_cache_set wp_cache_add wp_cache_flush wp_cache_delete; do
        if grep -qE "function[[:space:]]+${function_name}[[:space:]]*\(" -- "$drop_in" 2>/dev/null; then
            implemented+=("$function_name")
        fi
    done
    for backend in redis memcached apcu sqlite; do
        if grep -qi -- "$backend" "$drop_in" 2>/dev/null; then
            break
        fi
        backend='onbekend'
    done
    local head_sample
    head_sample=$(head -c 4000 -- "$drop_in" 2>/dev/null) || head_sample=''
    detect_wp_evaluate_text_signals "$head_sample"
    local strong_signal="$WP2SHELL_DETECT_WP_SIGNAL_CONFIDENCE"
    if [ "$strong_signal" = "$CONFIDENCE_HIGH" ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_CRITICAL" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=object-cache-dropin-suspect" \
            "title=De object-cache drop-in bevat een bevestigd achterdeurpatroon" \
            "detail=Het bestand wp-content/object-cache.php bevat een patroon uit de IOC-lijst. ${WP2SHELL_DETECT_WP_SIGNAL_EVIDENCE:-} Een drop-in laadt bij elke request en nog voor de plugins, dus dit is een volwaardige achterdeur en geen cacheconfiguratie." \
            "file=$drop_in" \
            "sha1=$digest" \
            "remediation=Behandel deze site als gecompromitteerd en plaats het bestand in de opschoonstap in quarantaine."
        detect_wp_mark_check_complete
        return 0
    fi
    if [ "${#implemented[@]}" -lt 3 ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_HIGH" \
            "confidence=$CONFIDENCE_HEURISTIC" \
            "category=object-cache-dropin-suspect" \
            "title=object-cache.php lijkt geen echte object cache te zijn" \
            "detail=Het bestand wp-content/object-cache.php definieert slechts ${#implemented[@]} van de verwachte cachefuncties. Een echte drop-in implementeert de volledige set wp_cache-functies. Een bestand op deze plek dat dat niet doet, gebruikt de naam van een drop-in om bij elke request geladen te worden." \
            "file=$drop_in" \
            "sha1=$digest" \
            "evidence=gevonden functies: $(detect_wp_join_with ", " "${implemented[@]+"${implemented[@]}"}")" \
            "remediation=Bekijk dit bestand handmatig en vergelijk het met de drop-in van de cacheplugin die de klant gebruikt."
        detect_wp_mark_check_complete
        return 0
    fi
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_INFO" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=object-cache-present" \
        "title=Persistente object cache aanwezig, uitsluitend als context" \
        "detail=Er staat een echte object-cache drop-in in wp-content (backend: $backend, ${#implemented[@]} cachefuncties). Dit is uitsluitend context bij de beoordeling en nadrukkelijk geen maatregel.$litespeed_note Een object cache maakt de site niet veilig en neemt geen van beide kwetsbaarheden weg: de stap naar code-uitvoering in deze keten heeft juist geen persistente object cache nodig, en de diefstal van gegevens via de SQL-injectie werkt hoe dan ook. Er zijn gehashte inloggegevens buitgemaakt voordat de details van de code-uitvoering openbaar waren." \
        "file=$drop_in" \
        "sha1=$digest" \
        "remediation=Behandel dit niet als maatregel. Bijwerken naar een gepatchte versie blijft nodig."
    detect_wp_mark_check_complete
    return 0
}

detect_wp_report_admin_truncation() {
    local site_path=$1
    if [ "${WP2SHELL_DETECT_WP_ADMIN_TRUNCATED:-0}" -le 0 ]; then
        return 0
    fi
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_MEDIUM" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=admin-list-truncated" \
        "title=Niet alle beheerdersaccounts zijn afzonderlijk gerapporteerd" \
        "detail=Er zijn ${WP2SHELL_DETECT_WP_ADMIN_TRUNCATED} beheerders buiten het blootstellingsvenster niet apart gerapporteerd omdat de limiet per controle bereikt was. Accounts die binnen het venster zijn aangemaakt worden nooit afgekapt en zijn dus wel volledig beoordeeld. Voor de overige accounts is deze lijst onvolledig." \
        "remediation=Verhoog de limiet per controle of beoordeel de volledige beheerderslijst met wp user list --role=administrator."
    return 0
}

detect_wp_mark_check_complete() {
    WP2SHELL_DETECT_WP_CHECK_COMPLETED=1
    return 0
}

detect_wp_run_child_check() {
    local label=$1
    shift
    local status=0
    WP2SHELL_DETECT_WP_CHECK_COMPLETED=0
    "$@" || status=$?
    if [ "$status" -ne 0 ]; then
        log_warn "$label is voortijdig gestopt met exitcode $status"
        WP2SHELL_DETECT_WP_FAILED_CHECKS+=("$label")
        return 0
    fi
    if [ "$WP2SHELL_DETECT_WP_CHECK_COMPLETED" != "1" ]; then
        log_warn "$label is gestopt zonder af te ronden"
        WP2SHELL_DETECT_WP_FAILED_CHECKS+=("$label")
    fi
    return 0
}

detect_wp_report_incomplete_checks() {
    local site_path=$1
    if [ "${#WP2SHELL_DETECT_WP_FAILED_CHECKS[@]}" -eq 0 ]; then
        return 0
    fi
    local joined
    joined=$(printf '%s, ' "${WP2SHELL_DETECT_WP_FAILED_CHECKS[@]}")
    joined=${joined%, }
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_MEDIUM" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=wp-checks-incomplete" \
        "title=Niet alle WordPress-controles zijn afgerond" \
        "detail=De volgende controles zijn voortijdig gestopt: $joined. Wat die controles hadden kunnen vinden is dus onbekend, en deze installatie mag op die punten niet als schoon gelden." \
        "evidence=$joined" \
        "remediation=Bekijk het runlogboek voor de oorzaak en draai de scan opnieuw voor deze site."
    return 0
}

detect_wp_report_scan_scope() {
    local site_path=$1 cli_version=$2
    detect_wp_report_admin_truncation "$site_path"
    local expected=${WP2SHELL_EXPECTED_WP_CLI_VERSION:-2.12.0}
    local detail
    detail="Uitgevoerde controles op deze installatie: core-integriteit (${WP2SHELL_DETECT_WP_CORE_STATUS:-niet uitgevoerd}),"
    detail="$detail toegevoegd ${WP2SHELL_DETECT_WP_CORE_ADDED:-0}, gewijzigd ${WP2SHELL_DETECT_WP_CORE_MODIFIED:-0}, ontbrekend ${WP2SHELL_DETECT_WP_CORE_MISSING:-0}."
    detail="$detail Plugin-integriteit (${WP2SHELL_DETECT_WP_PLUGIN_STATUS:-niet uitgevoerd}), afwijkingen ${WP2SHELL_DETECT_WP_PLUGIN_ISSUES:-0}, niet geverifieerd ${WP2SHELL_DETECT_WP_PLUGIN_SKIPPED:-0}."
    detail="$detail Beheerders: ${WP2SHELL_DETECT_WP_ADMIN_TOTAL:-0} gevonden, ${WP2SHELL_DETECT_WP_ADMIN_IN_WINDOW:-0} binnen het blootstellingsvenster."
    detail="$detail Databasecontroles: ${WP2SHELL_DETECT_WP_DB_STATUS:-niet uitgevoerd}. WP-CLI ${cli_version:-onbekend}."
    detail="$detail Buiten bereik van dit onderdeel: wp-content wordt door verify-checksums nooit gecontroleerd en voor themas bestaat geen checksumcommando. Geen bevinding hier betekent dus dat geen van deze controles is aangeslagen, niet dat de site schoon is."
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_INFO" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=wp-scan-scope" \
        "title=Reikwijdte van de WP-CLI- en databasecontroles" \
        "detail=$detail" \
        "remediation=Lees dit onderdeel samen met de bestandsscan en de logscan."
    if [ -n "$cli_version" ] && [ "$cli_version" != "$expected" ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=wp-cli-version-unexpected" \
            "title=WP-CLI wijkt af van de versie waarop de parser is afgestemd" \
            "detail=Deze server draait WP-CLI $cli_version, terwijl de uitvoerpatronen van verify-checksums zijn vastgesteld op $expected. Een andere versie kan de meldingen anders formuleren of naar een andere stroom schrijven, waardoor bevindingen gemist worden. De uitvoer is daarom uit zowel stdout als stderr gelezen, maar de dekking is niet gegarandeerd." \
            "remediation=Controleer de uitvoer van wp core verify-checksums handmatig op deze server en stem de parser af op deze versie."
    fi
    return 0
}

detect_wp_for_site() {
    local site_path=$1 owner_user=$2 expected_domain=${3:-}
    if [ -z "$site_path" ] || [ -z "$owner_user" ]; then
        log_error "detect_wp_for_site vereist een sitepad en een eigenaar"
        return "$EXIT_INTERNAL"
    fi
    if [ ! -d "$site_path" ]; then
        log_error "Sitepad bestaat niet: $site_path"
        return "$EXIT_INTERNAL"
    fi
    if [ -z "$expected_domain" ] && declare -F domain_from_path >/dev/null 2>&1; then
        expected_domain=$(domain_from_path "$site_path") || expected_domain=''
    fi
    local work_dir
    if ! work_dir=$(make_temp_dir wp2shell-detect-wp); then
        log_error "Kan geen werkmap maken voor de WP-CLI-controles van $site_path"
        return "$EXIT_INTERNAL"
    fi
    register_temp_cleanup "$work_dir"
    WP2SHELL_DETECT_WP_WORK_DIR="$work_dir"
    WP2SHELL_DETECT_WP_TABLE_PREFIX=""
    WP2SHELL_DETECT_WP_ACTIVE_PLUGINS_FILE=""
    WP2SHELL_DETECT_WP_CORE_ADDED=0
    WP2SHELL_DETECT_WP_CORE_MODIFIED=0
    WP2SHELL_DETECT_WP_CORE_MISSING=0
    WP2SHELL_DETECT_WP_CORE_STATUS='niet uitgevoerd'
    WP2SHELL_DETECT_WP_PLUGIN_ISSUES=0
    WP2SHELL_DETECT_WP_PLUGIN_SKIPPED=0
    WP2SHELL_DETECT_WP_PLUGIN_STATUS='niet uitgevoerd'
    WP2SHELL_DETECT_WP_ADMIN_TOTAL=0
    WP2SHELL_DETECT_WP_ADMIN_IN_WINDOW=0
    WP2SHELL_DETECT_WP_ADMIN_TRUNCATED=0
    WP2SHELL_DETECT_WP_DB_STATUS='niet uitgevoerd'
    log_info "WP-CLI- en databasecontroles voor $site_path als gebruiker $owner_user"
    if ! wp_is_functional "$owner_user" "$site_path"; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=wp-cli-unavailable" \
            "title=WP-CLI kan deze installatie niet benaderen" \
            "detail=wp core is-installed is mislukt voor deze installatie. Dat wijst op een beschadigde wp-config.php, een databaseserver die niet bereikbaar is, of een installatie die niet meer opstart. Geen van de controles op beheerders, autoloaded opties, geplande taken en core-integriteit heeft daardoor gedraaid. Deze installatie mag niet als schoon gerapporteerd worden." \
            "remediation=Controleer wp-config.php en de bereikbaarheid van de databaseserver, en draai de scan daarna opnieuw voor deze site." \
            "action=reported"
        rm -rf -- "$work_dir" 2>/dev/null || true
        WP2SHELL_DETECT_WP_WORK_DIR=""
        return 0
    fi
    local cli_version=''
    cli_version=$(detect_wp_cli_version "$site_path" "$owner_user") || cli_version=''
    WP2SHELL_DETECT_WP_FAILED_CHECKS=()
    detect_wp_run_child_check "core-integriteit" \
        detect_wp_core_checksums "$site_path" "$owner_user"
    detect_wp_run_child_check "plugin-integriteit" \
        detect_wp_plugin_checksums "$site_path" "$owner_user"
    detect_wp_run_child_check "themacontrole" \
        detect_wp_theme_checksum_gap "$site_path" "$owner_user"
    detect_wp_run_child_check "beheerdersaccounts" \
        detect_wp_administrator_accounts "$site_path" "$owner_user"
    detect_wp_run_child_check "actieve plugins" \
        detect_wp_check_active_plugins "$site_path" "$owner_user"
    detect_wp_run_child_check "databasepersistentie" \
        detect_wp_database_persistence "$site_path" "$owner_user" "$expected_domain"
    detect_wp_run_child_check "geplande taken" \
        detect_wp_scheduled_tasks "$site_path" "$owner_user"
    detect_wp_run_child_check "automatische updates" \
        detect_wp_auto_update_posture "$site_path"
    detect_wp_run_child_check "object cache" \
        detect_wp_object_cache_context "$site_path" "$owner_user"
    detect_wp_report_incomplete_checks "$site_path"
    detect_wp_report_scan_scope "$site_path" "$cli_version" \
        || log_warn "Kon de reikwijdte van de controles niet vastleggen voor $site_path"
    rm -rf -- "$work_dir" 2>/dev/null || true
    WP2SHELL_DETECT_WP_WORK_DIR=""
    return 0
}
