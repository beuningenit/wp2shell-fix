WP2SHELL_REPORT_LOADED=1

count_matching_field() {
    local file=$1 field=$2 value=$3
    if [ ! -s "$file" ]; then
        printf '0'
        return 0
    fi
    local result
    result=$(grep -c "\"$field\":\"$value\"" -- "$file" 2>/dev/null) || result=0
    case $result in
        ''|*[!0-9]*) result=0 ;;
    esac
    printf '%s' "$result"
    return 0
}

count_records() {
    local file=$1
    if [ ! -s "$file" ]; then
        printf '0'
        return 0
    fi
    local total
    total=$(grep -c '^{' -- "$file" 2>/dev/null) || total=0
    printf '%s' "$total"
}

ndjson_to_array() {
    local file=$1
    printf '['
    if [ -s "$file" ]; then
        local first=1 line
        while IFS= read -r line || [ -n "$line" ]; do
            if [ -z "$line" ]; then
                continue
            fi
            if [ "$first" = "1" ]; then
                first=0
            else
                printf ','
            fi
            printf '%s' "$line"
        done < "$file"
    fi
    printf ']'
    return 0
}

write_report_json() {
    local output=$1
    local hostname_value
    hostname_value=$(hostname -f 2>/dev/null || hostname 2>/dev/null) || hostname_value='onbekend'
    local worst
    worst=$(worst_severity_from_findings)
    {
        printf '{'
        printf '"run_id":%s,' "$(json_string "${WP2SHELL_RUN_ID:-}")"
        printf '"toolkit_version":%s,' "$(json_string "${WP2SHELL_TOOLKIT_VERSION:-}")"
        printf '"hostname":%s,' "$(json_string "$hostname_value")"
        printf '"subcommand":%s,' "$(json_string "${OPT_SUBCOMMAND:-scan}")"
        printf '"apply_mode":%s,' "$(json_bool "${OPT_APPLY:-0}")"
        printf '"started_at":%s,' "$(json_string "${WP2SHELL_STARTED_AT:-}")"
        printf '"finished_at":%s,' "$(json_string "${WP2SHELL_FINISHED_AT:-}")"
        printf '"worst_severity":%s,' "$(json_string "$worst")"
        printf '"summary":{'
        printf '"sites_total":%s,' "$(count_records "$WP2SHELL_SITES_FILE")"
        printf '"findings_total":%s,' "$(count_records "$WP2SHELL_FINDINGS_FILE")"
        printf '"sites_rce_vulnerable":%s,' \
            "$(count_matching_field "$WP2SHELL_SITES_FILE" wp2shell_status "$WP2SHELL_STATUS_RCE_VULNERABLE")"
        printf '"sites_sqli_latent":%s,' \
            "$(count_matching_field "$WP2SHELL_SITES_FILE" wp2shell_status "$WP2SHELL_STATUS_SQLI_LATENT")"
        printf '"sites_wp2shell_patched":%s,' \
            "$(count_matching_field "$WP2SHELL_SITES_FILE" wp2shell_status "$WP2SHELL_STATUS_PATCHED")"
        printf '"sites_not_affected":%s,' \
            "$(count_matching_field "$WP2SHELL_SITES_FILE" wp2shell_status "$WP2SHELL_STATUS_NOT_AFFECTED")"
        printf '"sites_security_outdated":%s,' \
            "$(count_matching_field "$WP2SHELL_SITES_FILE" security_status "$WP2SHELL_SECURITY_OUTDATED")"
        printf '"findings_critical":%s,' \
            "$(count_matching_field "$WP2SHELL_FINDINGS_FILE" severity "$SEVERITY_CRITICAL")"
        printf '"findings_high":%s,' \
            "$(count_matching_field "$WP2SHELL_FINDINGS_FILE" severity "$SEVERITY_HIGH")"
        printf '"findings_medium":%s,' \
            "$(count_matching_field "$WP2SHELL_FINDINGS_FILE" severity "$SEVERITY_MEDIUM")"
        printf '"findings_low":%s,' \
            "$(count_matching_field "$WP2SHELL_FINDINGS_FILE" severity "$SEVERITY_LOW")"
        printf '"findings_info":%s,' \
            "$(count_matching_field "$WP2SHELL_FINDINGS_FILE" severity "$SEVERITY_INFO")"
        printf '"findings_high_confidence":%s' \
            "$(count_matching_field "$WP2SHELL_FINDINGS_FILE" confidence "$CONFIDENCE_HIGH")"
        printf '},'
        printf '"sites":'
        ndjson_to_array "$WP2SHELL_SITES_FILE"
        printf ','
        printf '"findings":'
        ndjson_to_array "$WP2SHELL_FINDINGS_FILE"
        printf '}'
        printf '\n'
    } > "$output"
    chmod 0640 -- "$output" 2>/dev/null || true
    return 0
}

findings_for_site() {
    local site_path=$1 minimum_rank=${2:-0}
    if [ ! -s "$WP2SHELL_FINDINGS_FILE" ]; then
        return 0
    fi
    local line record_site rank
    while IFS= read -r line || [ -n "$line" ]; do
        if [ -z "$line" ]; then
            continue
        fi
        record_site=$(json_extract_field "$line" site_path) || record_site=''
        if [ "$record_site" != "$site_path" ]; then
            continue
        fi
        rank=$(json_extract_field "$line" severity_rank) || rank=0
        case $rank in
            ''|*[!0-9]*) rank=0 ;;
        esac
        if [ "$rank" -lt "$minimum_rank" ]; then
            continue
        fi
        printf '%s\n' "$line"
    done < "$WP2SHELL_FINDINGS_FILE"
    return 0
}

sort_findings_by_severity() {
    local input=$1
    if [ ! -s "$input" ]; then
        return 0
    fi
    local line rank
    while IFS= read -r line || [ -n "$line" ]; do
        if [ -z "$line" ]; then
            continue
        fi
        rank=$(json_extract_field "$line" severity_rank) || rank=0
        case $rank in
            ''|*[!0-9]*) rank=0 ;;
        esac
        printf '%s\t%s\n' "$rank" "$line"
    done < "$input" | sort -rn -k1,1 | cut -f2-
    return 0
}

wrap_text() {
    local text=$1 width=${2:-96} indent=${3:-}
    local line
    while IFS= read -r line || [ -n "$line" ]; do
        printf '%s%s\n' "$indent" "$line"
    done < <(printf '%s\n' "$text" | fold -s -w "$width")
    return 0
}

render_site_section() {
    local record=$1
    local site_path version status security domain url owner target subinstall
    site_path=$(json_extract_field "$record" site_path) || site_path=''
    version=$(json_extract_field "$record" version) || version=''
    status=$(json_extract_field "$record" wp2shell_status) || status=''
    security=$(json_extract_field "$record" security_status) || security=''
    domain=$(json_extract_field "$record" domain) || domain=''
    url=$(json_extract_field "$record" url) || url=''
    owner=$(json_extract_field "$record" effective_user) || owner=''
    target=$(json_extract_field "$record" target_version) || target=''
    subinstall=$(json_extract_field "$record" is_subinstall) || subinstall='false'
    printf '\n'
    printf -- '----------------------------------------------------------------------------------------\n'
    if [ -n "$domain" ]; then
        printf 'Site      : %s\n' "$domain"
    fi
    printf 'Pad       : %s\n' "$site_path"
    if [ -n "$url" ]; then
        printf 'Url       : %s\n' "$url"
    fi
    printf 'Eigenaar  : %s\n' "$owner"
    if [ "$subinstall" = "true" ]; then
        printf 'Type      : subinstallatie in een submap\n'
    fi
    if [ -n "$version" ]; then
        printf 'Versie    : %s\n' "$version"
    else
        printf 'Versie    : niet leesbaar\n'
    fi
    if [ -n "$status" ]; then
        printf 'wp2shell  : %s\n' "$(wp2shell_status_dutch_label "$status")"
    fi
    if [ -n "$security" ]; then
        printf 'Security  : %s\n' "$(security_status_dutch_label "$security")"
    fi
    if [ -n "$target" ] && [ "$security" != "$WP2SHELL_SECURITY_CURRENT" ]; then
        printf 'Advies    : bijwerken naar %s\n' "$target"
    fi
    local site_findings temp_file
    temp_file=$(mktemp)
    findings_for_site "$site_path" > "$temp_file"
    if [ -s "$temp_file" ]; then
        printf 'Bevindingen:\n'
        local line severity confidence title detail remediation file_path action
        while IFS= read -r line || [ -n "$line" ]; do
            if [ -z "$line" ]; then
                continue
            fi
            severity=$(json_extract_field "$line" severity) || severity=''
            confidence=$(json_extract_field "$line" confidence) || confidence=''
            title=$(json_extract_field "$line" title) || title=''
            detail=$(json_extract_field "$line" detail) || detail=''
            remediation=$(json_extract_field "$line" remediation) || remediation=''
            file_path=$(json_extract_field "$line" file_path) || file_path=''
            action=$(json_extract_field "$line" action) || action=''
            printf '  [%s] %s\n' "$(severity_dutch_label "$severity")" "$title"
            printf '      zekerheid: %s\n' "$(confidence_dutch_label "$confidence")"
            if [ -n "$file_path" ]; then
                printf '      bestand: %s\n' "$file_path"
            fi
            if [ -n "$detail" ]; then
                wrap_text "$detail" 84 '      '
            fi
            if [ -n "$remediation" ]; then
                printf '      actie: %s\n' "$remediation"
            fi
            if [ -n "$action" ] && [ "$action" != "reported" ]; then
                printf '      uitgevoerd: %s\n' "$action"
            fi
            printf '\n'
        done < <(sort_findings_by_severity "$temp_file")
    else
        printf 'Bevindingen: geen\n'
    fi
    rm -f -- "$temp_file"
    return 0
}

render_dutch_summary() {
    local output=$1
    local hostname_value worst sites_total
    hostname_value=$(hostname -f 2>/dev/null || hostname 2>/dev/null) || hostname_value='onbekend'
    worst=$(worst_severity_from_findings)
    sites_total=$(count_records "$WP2SHELL_SITES_FILE")
    {
        printf '========================================================================================\n'
        printf 'wp2shell rapport\n'
        printf '========================================================================================\n'
        printf 'Server        : %s\n' "$hostname_value"
        printf 'Datum         : %s\n' "$(timestamp_dutch)"
        printf 'Run           : %s\n' "${WP2SHELL_RUN_ID:-}"
        printf 'Subcommando   : %s\n' "${OPT_SUBCOMMAND:-scan}"
        if [ "${OPT_APPLY:-0}" = "1" ]; then
            printf 'Modus         : wijzigend, --apply was ingeschakeld\n'
        else
            printf 'Modus         : rapportage, er is niets gewijzigd\n'
        fi
        printf 'Zwaarste      : %s\n' "$(severity_dutch_label "$worst")"
        printf '\n'
        printf 'Overzicht\n'
        printf -- '----------------------------------------------------------------------------------------\n'
        printf 'WordPress-installaties gevonden      : %s\n' "$sites_total"
        printf 'Kwetsbaar voor de RCE-keten          : %s\n' \
            "$(count_matching_field "$WP2SHELL_SITES_FILE" wp2shell_status "$WP2SHELL_STATUS_RCE_VULNERABLE")"
        printf 'Kwetsbaar voor de SQL-injectie       : %s\n' \
            "$(count_matching_field "$WP2SHELL_SITES_FILE" wp2shell_status "$WP2SHELL_STATUS_SQLI_LATENT")"
        printf 'Gepatcht tegen wp2shell              : %s\n' \
            "$(count_matching_field "$WP2SHELL_SITES_FILE" wp2shell_status "$WP2SHELL_STATUS_PATCHED")"
        printf 'Niet geraakt door wp2shell           : %s\n' \
            "$(count_matching_field "$WP2SHELL_SITES_FILE" wp2shell_status "$WP2SHELL_STATUS_NOT_AFFECTED")"
        printf 'Mist de securityrelease van 6 aug    : %s\n' \
            "$(count_matching_field "$WP2SHELL_SITES_FILE" security_status "$WP2SHELL_SECURITY_OUTDATED")"
        printf '\n'
        printf 'Bevindingen naar ernst\n'
        printf -- '----------------------------------------------------------------------------------------\n'
        printf 'Kritiek       : %s\n' "$(count_matching_field "$WP2SHELL_FINDINGS_FILE" severity "$SEVERITY_CRITICAL")"
        printf 'Hoog          : %s\n' "$(count_matching_field "$WP2SHELL_FINDINGS_FILE" severity "$SEVERITY_HIGH")"
        printf 'Middel        : %s\n' "$(count_matching_field "$WP2SHELL_FINDINGS_FILE" severity "$SEVERITY_MEDIUM")"
        printf 'Laag          : %s\n' "$(count_matching_field "$WP2SHELL_FINDINGS_FILE" severity "$SEVERITY_LOW")"
        printf 'Informatief   : %s\n' "$(count_matching_field "$WP2SHELL_FINDINGS_FILE" severity "$SEVERITY_INFO")"
        printf '\n'
        printf 'Bevestigde bevindingen               : %s\n' \
            "$(count_matching_field "$WP2SHELL_FINDINGS_FILE" confidence "$CONFIDENCE_HIGH")"
        printf 'Heuristisch, handmatige review nodig : %s\n' \
            "$(count_matching_field "$WP2SHELL_FINDINGS_FILE" confidence "$CONFIDENCE_HEURISTIC")"
        printf '\n'
        printf 'Per installatie\n'
        printf '========================================================================================\n'
        if [ -s "$WP2SHELL_SITES_FILE" ]; then
            local line
            while IFS= read -r line || [ -n "$line" ]; do
                if [ -n "$line" ]; then
                    render_site_section "$line"
                fi
            done < "$WP2SHELL_SITES_FILE"
        else
            printf '\nGeen WordPress-installaties gevonden.\n'
        fi
        printf '\n'
        printf '========================================================================================\n'
        printf 'Belangrijk\n'
        printf '========================================================================================\n'
        wrap_text "Gepatcht betekent niet schoon. Een installatie die tijdens het blootstellingsvenster op een kwetsbare versie stond en vanaf internet bereikbaar was, kan al voor het patchen zijn misbruikt. Voor die sites geldt dat admin-wachtwoordhashes en andere gegevens uitgelezen kunnen zijn." 88
        printf '\n'
        wrap_text "Heuristische bevindingen zijn signalen, geen bewijs. Legitieme plugins gebruiken ook base64_decode en gzinflate. Beoordeel ze handmatig voordat er iets verwijderd wordt." 88
        printf '\n'
        printf 'Volledige machineleesbare uitvoer: %s\n' "${WP2SHELL_REPORT_JSON:-}"
        printf 'Auditlog: %s\n' "${WP2SHELL_AUDIT_LOG:-}"
        printf '\n'
    } > "$output"
    chmod 0640 -- "$output" 2>/dev/null || true
    return 0
}
