WP2SHELL_DETECT_FILES_LOADED=1

WP2SHELL_DETECT_FILES_LIB_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd) || WP2SHELL_DETECT_FILES_LIB_DIR=""

WP2SHELL_FILE_IOCS_LOADED=0
WP2SHELL_FILE_IOC_LOAD_FAILED=0
WP2SHELL_FILE_IOC_WARNING_REPORTED=0
WP2SHELL_FILE_IOC_PATTERN_FILE=""

WP2SHELL_DETECT_FILES_PRINTF_SUPPORT=""
WP2SHELL_DETECT_FILES_SHA256_TOOL=""

WP2SHELL_DETECT_FILES_SIGNAL_COUNT=0
WP2SHELL_DETECT_FILES_SIGNAL_LABELS=()
WP2SHELL_DETECT_FILES_CURRENT_SHA1=""
WP2SHELL_DETECT_FILES_CURRENT_SHA256=""
WP2SHELL_DETECT_FILES_HIGH_REPORTED=0

WP2SHELL_DETECT_FILES_ONELINER_MAX_BYTES=2048
WP2SHELL_DETECT_FILES_MINIMAL_DROPPER_MIN_BYTES=700
WP2SHELL_DETECT_FILES_MINIMAL_DROPPER_MAX_BYTES=2400
WP2SHELL_DETECT_FILES_PACKED_SHELL_MIN_BYTES=110000
WP2SHELL_DETECT_FILES_PACKED_SHELL_MAX_BYTES=200000

WP2SHELL_DETECT_FILES_PRUNE_FALLBACK_NAMES=(
    "node_modules"
    ".git"
    ".svn"
    ".wp-cli"
    "wp2shell-quarantine"
    "wp2shell-backup"
)

declare -gA WP2SHELL_FILE_IOC_SHA1=()
declare -gA WP2SHELL_FILE_IOC_SHA256=()
declare -gA WP2SHELL_FILE_IOC_PATTERN_CATEGORY=()
declare -gA WP2SHELL_FILE_IOC_PATTERN_CONFIDENCE=()
declare -gA WP2SHELL_DETECT_FILES_CLAMAV_HITS=()
declare -gA WP2SHELL_DETECT_FILES_PLUGIN_OPEN_REST=()
declare -gA WP2SHELL_DETECT_FILES_PLUGIN_OPEN_REST_EVIDENCE=()
declare -gA WP2SHELL_DETECT_FILES_PLUGIN_EXEC_SINK=()
declare -gA WP2SHELL_DETECT_FILES_PLUGIN_EXEC_SINK_EVIDENCE=()

file_ioc_directory() {
    if [ -n "${WP2SHELL_IOC_DIR:-}" ] && [ -d "$WP2SHELL_IOC_DIR" ]; then
        printf '%s' "$WP2SHELL_IOC_DIR"
        return 0
    fi
    if [ -n "${WP2SHELL_ROOT:-}" ] && [ -d "$WP2SHELL_ROOT/config/iocs" ]; then
        printf '%s' "$WP2SHELL_ROOT/config/iocs"
        return 0
    fi
    if [ -n "$WP2SHELL_DETECT_FILES_LIB_DIR" ] && [ -d "$WP2SHELL_DETECT_FILES_LIB_DIR/../config/iocs" ]; then
        printf '%s' "$WP2SHELL_DETECT_FILES_LIB_DIR/../config/iocs"
        return 0
    fi
    return 1
}

load_file_ioc_hashes() {
    local source_file=$1
    if [ ! -r "$source_file" ]; then
        log_warn "IOC-bestand met hashes ontbreekt of is onleesbaar: $source_file"
        return 1
    fi
    local line algorithm hash_value confidence category source_name loaded=0
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%$'\r'}
        case $line in
            ''|'#'*) continue ;;
        esac
        IFS=: read -r algorithm hash_value confidence category source_name <<<"$line"
        hash_value=${hash_value,,}
        confidence=${confidence:-high}
        category=${category:-onbekend}
        source_name=${source_name:-onbekend}
        case $algorithm in
            sha1)
                if [ "${#hash_value}" -eq 40 ]; then
                    WP2SHELL_FILE_IOC_SHA1["$hash_value"]="$confidence|$category|$source_name"
                    loaded=$((loaded + 1))
                fi
                ;;
            sha256)
                if [ "${#hash_value}" -eq 64 ]; then
                    WP2SHELL_FILE_IOC_SHA256["$hash_value"]="$confidence|$category|$source_name"
                    loaded=$((loaded + 1))
                fi
                ;;
            *)
                log_debug "Onbekend hashalgoritme in $source_file: $algorithm"
                ;;
        esac
    done < "$source_file"
    if [ "$loaded" -eq 0 ]; then
        log_warn "Geen bruikbare hashes gelezen uit $source_file"
        return 1
    fi
    log_debug "$loaded hash-IOCs geladen uit $source_file"
    return 0
}

load_file_ioc_patterns() {
    local source_file=$1
    if [ ! -r "$source_file" ]; then
        log_warn "IOC-bestand met codepatronen ontbreekt of is onleesbaar: $source_file"
        return 1
    fi
    local pattern_file
    pattern_file=$(mktemp -t wp2shell-patterns.XXXXXXXX) || return 1
    register_temp_cleanup "$pattern_file"
    : > "$pattern_file"
    local line category confidence literal loaded=0
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%$'\r'}
        case $line in
            ''|'#'*) continue ;;
        esac
        IFS=: read -r category confidence literal <<<"$line"
        if [ -z "$category" ] || [ -z "$confidence" ] || [ -z "$literal" ]; then
            log_debug "Regel overgeslagen in $source_file: $line"
            continue
        fi
        WP2SHELL_FILE_IOC_PATTERN_CATEGORY["$literal"]="$category"
        WP2SHELL_FILE_IOC_PATTERN_CONFIDENCE["$literal"]="$confidence"
        printf '%s\n' "$literal" >> "$pattern_file"
        loaded=$((loaded + 1))
    done < "$source_file"
    if [ "$loaded" -eq 0 ]; then
        log_warn "Geen bruikbare codepatronen gelezen uit $source_file"
        rm -f -- "$pattern_file"
        return 1
    fi
    WP2SHELL_FILE_IOC_PATTERN_FILE="$pattern_file"
    log_debug "$loaded codepatronen geladen uit $source_file"
    return 0
}

load_file_iocs() {
    if [ "${WP2SHELL_FILE_IOCS_LOADED:-0}" = "1" ]; then
        return 0
    fi
    WP2SHELL_FILE_IOCS_LOADED=1
    local ioc_dir
    if ! ioc_dir=$(file_ioc_directory); then
        WP2SHELL_FILE_IOC_LOAD_FAILED=1
        log_error "Geen IOC-map gevonden, hash- en patroondetectie zijn niet beschikbaar"
        return 1
    fi
    local failures=0
    load_file_ioc_hashes "$ioc_dir/hashes.txt" || failures=$((failures + 1))
    load_file_ioc_patterns "$ioc_dir/code-patterns.txt" || failures=$((failures + 1))
    if [ "$failures" -gt 0 ]; then
        WP2SHELL_FILE_IOC_LOAD_FAILED=1
        return 1
    fi
    return 0
}

detect_files_report_ioc_gap() {
    local site_path=$1
    if [ "$WP2SHELL_FILE_IOC_LOAD_FAILED" != "1" ]; then
        return 0
    fi
    if [ "$WP2SHELL_FILE_IOC_WARNING_REPORTED" = "1" ]; then
        return 0
    fi
    WP2SHELL_FILE_IOC_WARNING_REPORTED=1
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_MEDIUM" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=ioc-data-missing" \
        "title=De IOC-bestanden konden niet geladen worden" \
        "detail=De bestandsscan draait zonder de gepubliceerde hashes of zonder de codepatronen uit config/iocs. Deze run kan besmettingen missen en een uitkomst zonder bevindingen mag niet als schoon gelezen worden." \
        "remediation=Controleer of config/iocs/hashes.txt en config/iocs/code-patterns.txt aanwezig en leesbaar zijn en draai de scan opnieuw."
    return 0
}

detect_files_is_php_candidate() {
    local lower=${1,,}
    case $lower in
        *.php|*.phtml|*.php3|*.php4|*.php5|*.php6|*.php7|*.php8|*.phps|*.phar|*.inc) return 0 ;;
    esac
    return 1
}

detect_files_is_executable_php_name() {
    local lower=${1,,}
    case $lower in
        *.php|*.phtml|*.php3|*.php4|*.php5|*.php6|*.php7|*.php8|*.phps|*.phar) return 0 ;;
    esac
    return 1
}

detect_files_sha256_tool() {
    if [ -n "$WP2SHELL_DETECT_FILES_SHA256_TOOL" ]; then
        printf '%s' "$WP2SHELL_DETECT_FILES_SHA256_TOOL"
        return 0
    fi
    if have_command sha256sum; then
        WP2SHELL_DETECT_FILES_SHA256_TOOL=sha256sum
    elif have_command openssl; then
        WP2SHELL_DETECT_FILES_SHA256_TOOL=openssl
    else
        WP2SHELL_DETECT_FILES_SHA256_TOOL=none
    fi
    printf '%s' "$WP2SHELL_DETECT_FILES_SHA256_TOOL"
    return 0
}

detect_files_strip_checksum_escape() {
    local value=$1
    printf '%s' "${value#\\}"
    return 0
}

file_sha256() {
    local target=$1 tool output
    tool=$(detect_files_sha256_tool)
    case $tool in
        sha256sum)
            output=$(sha256sum -- "$target" 2>/dev/null) || return 1
            detect_files_strip_checksum_escape "${output%% *}"
            return 0
            ;;
        openssl)
            output=$(openssl dgst -sha256 -- "$target" 2>/dev/null) || return 1
            printf '%s' "${output##* }"
            return 0
            ;;
    esac
    return 1
}

detect_files_evidence_snippet() {
    local raw=$1
    local limit=${WP2SHELL_HEURISTIC_EVIDENCE_CHARS:-200}
    raw=${raw//$'\t'/ }
    raw=${raw//$'\n'/ }
    while [ "${raw:0:1}" = " " ]; do
        raw=${raw:1}
    done
    if [ "${#raw}" -gt "$limit" ]; then
        raw="${raw:0:$limit}..."
    fi
    printf '%s' "$raw"
    return 0
}

detect_files_first_match_line() {
    local target=$1 literal=$2 line=''
    line=$(grep -F -n -m1 -e "$literal" -- "$target" 2>/dev/null) || line=''
    detect_files_evidence_snippet "$line"
    return 0
}

detect_files_contains_literal() {
    grep -F -q -m1 -e "$2" -- "$1" 2>/dev/null
}

detect_files_reset_file_state() {
    WP2SHELL_DETECT_FILES_SIGNAL_COUNT=0
    WP2SHELL_DETECT_FILES_SIGNAL_LABELS=()
    WP2SHELL_DETECT_FILES_CURRENT_SHA1=""
    WP2SHELL_DETECT_FILES_CURRENT_SHA256=""
    WP2SHELL_DETECT_FILES_HIGH_REPORTED=0
    return 0
}

detect_files_note_signal() {
    WP2SHELL_DETECT_FILES_SIGNAL_COUNT=$((WP2SHELL_DETECT_FILES_SIGNAL_COUNT + 1))
    WP2SHELL_DETECT_FILES_SIGNAL_LABELS+=("$1")
    return 0
}

detect_files_signal_summary() {
    if [ "${#WP2SHELL_DETECT_FILES_SIGNAL_LABELS[@]}" -eq 0 ]; then
        printf 'geen'
        return 0
    fi
    local label first=1
    for label in "${WP2SHELL_DETECT_FILES_SIGNAL_LABELS[@]}"; do
        if [ "$first" = "1" ]; then
            first=0
        else
            printf ', '
        fi
        printf '%s' "$label"
    done
    return 0
}

detect_files_confidence_for_signal_count() {
    if [ "$WP2SHELL_DETECT_FILES_SIGNAL_COUNT" -ge 2 ]; then
        printf '%s' "$CONFIDENCE_HIGH"
    else
        printf '%s' "$CONFIDENCE_HEURISTIC"
    fi
    return 0
}

detect_files_size_profile_label() {
    local size=$1
    if [ "$size" -ge "$WP2SHELL_DETECT_FILES_PACKED_SHELL_MIN_BYTES" ] &&
        [ "$size" -le "$WP2SHELL_DETECT_FILES_PACKED_SHELL_MAX_BYTES" ]; then
        printf 'omvang past bij de ingepakte CMSmap-variant van ongeveer 150 kilobyte'
        return 0
    fi
    if [ "$size" -ge "$WP2SHELL_DETECT_FILES_MINIMAL_DROPPER_MIN_BYTES" ] &&
        [ "$size" -le "$WP2SHELL_DETECT_FILES_MINIMAL_DROPPER_MAX_BYTES" ]; then
        printf 'omvang past bij de minimale dropper van ongeveer 1,3 kilobyte'
        return 0
    fi
    return 1
}

detect_files_suspicious_name_reason() {
    local name=$1
    local lower=${name,,}
    case $lower in
        cmsmap|cmsmap[-_.]*|*[-_.]cmsmap)
            printf 'CMSmap is een losstaande pentesttool en geen WordPress-plugin, een plugin of bestand met deze naam hoort hier niet'
            return 0
            ;;
    esac
    if [[ $lower =~ ^wp2shell[-_][0-9a-f]{6,}(\.[a-z0-9]+)?$ ]]; then
        printf 'de naam volgt het waargenomen sjabloon wp2shell met een hexadecimaal achtervoegsel'
        return 0
    fi
    case $lower in
        *wp2shell*)
            printf 'de naam bevat wp2shell, de aanduiding van deze campagne'
            return 0
            ;;
        gg-*)
            printf 'de gg prefix is waargenomen bij plugins die via wp2shell zijn geplaatst'
            return 0
            ;;
        temp-write-test-*)
            printf 'dit is een schrijftest, aanvallers gebruiken die om te controleren of een map beschrijfbaar is, maar WordPress zelf laat bij een afgebroken update ook zulke bestanden achter'
            return 0
            ;;
    esac
    return 1
}

detect_files_plugin_directory_for() {
    local site_path=$1 relative=$2 remainder plugin_name
    case $relative in
        wp-content/plugins/*/*)
            remainder=${relative#wp-content/plugins/}
            plugin_name=${remainder%%/*}
            if [ -n "$plugin_name" ]; then
                printf '%s/wp-content/plugins/%s' "$site_path" "$plugin_name"
                return 0
            fi
            ;;
        wp-content/mu-plugins/*/*)
            remainder=${relative#wp-content/mu-plugins/}
            plugin_name=${remainder%%/*}
            if [ -n "$plugin_name" ]; then
                printf '%s/wp-content/mu-plugins/%s' "$site_path" "$plugin_name"
                return 0
            fi
            ;;
    esac
    return 1
}

detect_files_build_prune_arguments() {
    WP2SHELL_DETECT_FILES_PRUNE_ARGS=()
    local -a names=()
    if [ -n "${WP2SHELL_PRUNE_DIR_NAMES[*]+x}" ]; then
        names=("${WP2SHELL_PRUNE_DIR_NAMES[@]}")
    fi
    if [ "${#names[@]}" -eq 0 ]; then
        names=("${WP2SHELL_DETECT_FILES_PRUNE_FALLBACK_NAMES[@]}")
    fi
    local name first=1
    WP2SHELL_DETECT_FILES_PRUNE_ARGS+=('(')
    for name in "${names[@]}"; do
        if [ "$first" = "1" ]; then
            first=0
        else
            WP2SHELL_DETECT_FILES_PRUNE_ARGS+=(-o)
        fi
        WP2SHELL_DETECT_FILES_PRUNE_ARGS+=(-name "$name")
    done
    WP2SHELL_DETECT_FILES_PRUNE_ARGS+=(')' -prune -o)
    return 0
}

detect_files_build_name_arguments() {
    WP2SHELL_DETECT_FILES_NAME_ARGS=(
        '('
        -iname '*.php'
        -o -iname '*.phtml'
        -o -iname '*.php3'
        -o -iname '*.php4'
        -o -iname '*.php5'
        -o -iname '*.php6'
        -o -iname '*.php7'
        -o -iname '*.php8'
        -o -iname '*.phps'
        -o -iname '*.phar'
        -o -iname '*.inc'
        -o -iname '*.zip'
        -o -name '.htaccess'
        -o -name '.user.ini'
        -o -name 'temp-write-test-*'
        -o -path '*/wp-content/mu-plugins/*'
        ')'
    )
    return 0
}

detect_files_supports_find_printf() {
    if [ -n "$WP2SHELL_DETECT_FILES_PRINTF_SUPPORT" ]; then
        printf '%s' "$WP2SHELL_DETECT_FILES_PRINTF_SUPPORT"
        return 0
    fi
    if find -P /dev/null -maxdepth 0 -printf '%s' >/dev/null 2>&1; then
        WP2SHELL_DETECT_FILES_PRINTF_SUPPORT=1
    else
        WP2SHELL_DETECT_FILES_PRINTF_SUPPORT=0
    fi
    printf '%s' "$WP2SHELL_DETECT_FILES_PRINTF_SUPPORT"
    return 0
}

detect_files_load_prefix() {
    if [ -z "${WP2SHELL_LOAD_PREFIX[*]+x}" ]; then
        build_load_prefix
    fi
    return 0
}

detect_files_collect_candidates() {
    local site_path=$1 destination=$2
    detect_files_build_prune_arguments
    detect_files_build_name_arguments
    detect_files_load_prefix
    local -a prefix=()
    if [ -n "${WP2SHELL_LOAD_PREFIX[*]+x}" ]; then
        prefix=("${WP2SHELL_LOAD_PREFIX[@]}")
    fi
    : > "$destination"
    local status=0
    if [ "$(detect_files_supports_find_printf)" = "1" ]; then
        "${prefix[@]+"${prefix[@]}"}" find -P "$site_path" \
            "${WP2SHELL_DETECT_FILES_PRUNE_ARGS[@]}" \
            -type f "${WP2SHELL_DETECT_FILES_NAME_ARGS[@]}" \
            -printf '%s\0%p\0' > "$destination" 2>/dev/null || status=$?
        return "$status"
    fi
    local raw_list
    raw_list=$(mktemp -t wp2shell-rawlist.XXXXXXXX) || return 1
    register_temp_cleanup "$raw_list"
    "${prefix[@]+"${prefix[@]}"}" find -P "$site_path" \
        "${WP2SHELL_DETECT_FILES_PRUNE_ARGS[@]}" \
        -type f "${WP2SHELL_DETECT_FILES_NAME_ARGS[@]}" \
        -print0 > "$raw_list" 2>/dev/null || status=$?
    local candidate size
    while IFS= read -r -d '' candidate; do
        size=$(file_size_bytes "$candidate") || size=0
        printf '%s\0%s\0' "${size:-0}" "$candidate" >> "$destination"
    done < "$raw_list"
    rm -f -- "$raw_list"
    return "$status"
}

detect_files_clamav_scanner() {
    if [ "${WP2SHELL_CLAMAV_ENABLED:-0}" != "1" ]; then
        return 1
    fi
    if [ "${WP2SHELL_HAS_CLAMDSCAN:-0}" = "1" ]; then
        printf 'clamdscan'
        return 0
    fi
    if [ "${WP2SHELL_HAS_CLAMSCAN:-0}" = "1" ]; then
        printf 'clamscan'
        return 0
    fi
    return 1
}

detect_files_run_clamav_corroboration() {
    local listing=$1 owner_user=$2
    WP2SHELL_DETECT_FILES_CLAMAV_HITS=()
    local scanner
    if ! scanner=$(detect_files_clamav_scanner); then
        return 0
    fi
    local cap=${WP2SHELL_CLAMAV_MAX_FILE_BYTES:-26214400}
    local list result size candidate base queued=0 status=0
    list=$(mktemp -t wp2shell-clamav-list.XXXXXXXX) || return 1
    register_temp_cleanup "$list"
    : > "$list"
    while IFS= read -r -d '' size && IFS= read -r -d '' candidate; do
        case $size in
            ''|*[!0-9]*) continue ;;
        esac
        if [ "$size" -eq 0 ] || [ "$size" -gt "$cap" ]; then
            continue
        fi
        base=${candidate##*/}
        if ! detect_files_is_php_candidate "$base"; then
            continue
        fi
        case $candidate in
            *$'\n'*)
                log_debug "Pad met een newline wordt niet aan ClamAV aangeboden: $candidate"
                continue
                ;;
        esac
        printf '%s\n' "$candidate" >> "$list"
        queued=$((queued + 1))
    done < "$listing"
    if [ "$queued" -eq 0 ]; then
        rm -f -- "$list"
        return 0
    fi
    result=$(mktemp -t wp2shell-clamav-out.XXXXXXXX) || return 1
    register_temp_cleanup "$result"
    local scan_user=$owner_user
    if [ -z "$scan_user" ] || ! user_exists "$scan_user"; then
        scan_user=$(current_user_name)
    fi
    if [ "$scanner" = "clamdscan" ]; then
        run_as_user "$scan_user" clamdscan --no-summary --fdpass --file-list="$list" \
            > "$result" 2>/dev/null || status=$?
    else
        run_as_user "$scan_user" clamscan --no-summary --infected --file-list="$list" \
            > "$result" 2>/dev/null || status=$?
    fi
    if [ "$status" -gt 1 ]; then
        log_warn "ClamAV gaf exitcode $status, de scan gaat verder zonder deze bevestiging"
    fi
    local line hit_path signature
    while IFS= read -r line || [ -n "$line" ]; do
        case $line in
            *' FOUND') ;;
            *) continue ;;
        esac
        hit_path=${line% FOUND}
        signature=${hit_path##*: }
        hit_path=${hit_path%: *}
        if [ -n "$hit_path" ]; then
            WP2SHELL_DETECT_FILES_CLAMAV_HITS["$hit_path"]="$signature"
        fi
    done < "$result"
    rm -f -- "$list" "$result"
    return 0
}

detect_files_report_clamav_hit() {
    local site_path=$1 candidate=$2
    local signature=${WP2SHELL_DETECT_FILES_CLAMAV_HITS["$candidate"]:-}
    if [ -z "$signature" ]; then
        return 0
    fi
    detect_files_note_signal "clamav-detectie $signature"
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_HIGH" \
        "confidence=$CONFIDENCE_HEURISTIC" \
        "category=clamav-detection" \
        "title=ClamAV meldt een detectie op dit bestand" \
        "detail=ClamAV herkent dit bestand als $signature. Dit telt als bevestigend signaal naast de eigen detectie. Let op dat de standaardsignatures van ClamAV zwak zijn op PHP-webshells, dus het uitblijven van een melding zegt niets." \
        "file=$candidate" \
        "sha1=$WP2SHELL_DETECT_FILES_CURRENT_SHA1" \
        "evidence=$signature" \
        "remediation=Beoordeel dit bestand handmatig en zet het in quarantaine als het geen onderdeel van de site is."
    return 0
}

detect_files_note_location_signals() {
    local relative=$1
    case $relative in
        wp-content/uploads/*) detect_files_note_signal "locatie wp-content/uploads" ;;
        wp-content/cache/*) detect_files_note_signal "locatie wp-content/cache" ;;
        wp-content/upgrade/*) detect_files_note_signal "locatie wp-content/upgrade" ;;
        wp-content/mu-plugins/*) detect_files_note_signal "locatie wp-content/mu-plugins" ;;
    esac
    return 0
}

detect_files_compute_hashes() {
    local candidate=$1
    WP2SHELL_DETECT_FILES_CURRENT_SHA1=$(file_sha1 "$candidate") || WP2SHELL_DETECT_FILES_CURRENT_SHA1=""
    WP2SHELL_DETECT_FILES_CURRENT_SHA1=${WP2SHELL_DETECT_FILES_CURRENT_SHA1,,}
    WP2SHELL_DETECT_FILES_CURRENT_SHA1=${WP2SHELL_DETECT_FILES_CURRENT_SHA1#\\}
    if [ "${#WP2SHELL_DETECT_FILES_CURRENT_SHA1}" -ne 40 ]; then
        WP2SHELL_DETECT_FILES_CURRENT_SHA1=""
    fi
    if [ "${#WP2SHELL_FILE_IOC_SHA256[@]}" -gt 0 ]; then
        WP2SHELL_DETECT_FILES_CURRENT_SHA256=$(file_sha256 "$candidate") || WP2SHELL_DETECT_FILES_CURRENT_SHA256=""
        WP2SHELL_DETECT_FILES_CURRENT_SHA256=${WP2SHELL_DETECT_FILES_CURRENT_SHA256,,}
        if [ "${#WP2SHELL_DETECT_FILES_CURRENT_SHA256}" -ne 64 ]; then
            WP2SHELL_DETECT_FILES_CURRENT_SHA256=""
        fi
    fi
    return 0
}

detect_files_report_hash_match() {
    local site_path=$1 candidate=$2
    local entry='' algorithm=''
    if [ -n "$WP2SHELL_DETECT_FILES_CURRENT_SHA1" ]; then
        entry=${WP2SHELL_FILE_IOC_SHA1["$WP2SHELL_DETECT_FILES_CURRENT_SHA1"]:-}
        algorithm=sha1
    fi
    if [ -z "$entry" ] && [ -n "$WP2SHELL_DETECT_FILES_CURRENT_SHA256" ]; then
        entry=${WP2SHELL_FILE_IOC_SHA256["$WP2SHELL_DETECT_FILES_CURRENT_SHA256"]:-}
        algorithm=sha256
    fi
    if [ -z "$entry" ]; then
        return 0
    fi
    local category=${entry#*|}
    local source_name=${category#*|}
    category=${category%%|*}
    local shown_hash="$WP2SHELL_DETECT_FILES_CURRENT_SHA1"
    if [ "$algorithm" = "sha256" ]; then
        shown_hash="$WP2SHELL_DETECT_FILES_CURRENT_SHA256"
    fi
    detect_files_note_signal "hashmatch $algorithm"
    WP2SHELL_DETECT_FILES_HIGH_REPORTED=1
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_CRITICAL" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=known-malware-hash" \
        "title=Bekende wp2shell-malware herkend op hash" \
        "detail=De $algorithm van dit bestand komt exact overeen met een gepubliceerde indicator uit de categorie $category, gemeld door $source_name. Dit is een bevestigde besmetting en geen heuristiek. Let wel op dat de aanvaller de payload ingepakt aflevert, dus een ongewijzigde hash bewijst besmetting maar een afwijkende hash bewijst niets." \
        "file=$candidate" \
        "sha1=$WP2SHELL_DETECT_FILES_CURRENT_SHA1" \
        "evidence=$algorithm $shown_hash" \
        "remediation=Zet dit bestand in quarantaine, behandel de hele installatie als gecompromitteerd, roteer wachtwoorden en controleer de adminaccounts."
    return 0
}

detect_files_report_mu_plugin_file() {
    local site_path=$1 relative=$2 candidate=$3
    case $relative in
        wp-content/mu-plugins/*) ;;
        *) return 0 ;;
    esac
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_MEDIUM" \
        "confidence=$CONFIDENCE_HEURISTIC" \
        "category=mu-plugin-present" \
        "title=Bestand in mu-plugins aangetroffen" \
        "detail=Bestanden in wp-content/mu-plugins worden bij elke aanvraag geladen zonder dat ze in de beheerinterface aan of uit te zetten zijn. Dat maakt de map een geliefde plek voor persistentie. Dit is geen bewijs van besmetting, elk bestand hier moet handmatig herkend worden als iets dat de sitebeheerder zelf heeft geplaatst." \
        "file=$candidate" \
        "sha1=$WP2SHELL_DETECT_FILES_CURRENT_SHA1" \
        "remediation=Stel per bestand vast welke plugin of beheerder het geplaatst heeft en verwijder wat niet thuishoort."
    return 0
}

detect_files_report_php_in_writable_directory() {
    local site_path=$1 relative=$2 candidate=$3 size=$4
    if [ "${WP2SHELL_SCAN_UPLOADS_PHP:-1}" != "1" ]; then
        return 0
    fi
    local location=''
    case $relative in
        wp-content/uploads/*) location='wp-content/uploads' ;;
        wp-content/cache/*) location='wp-content/cache' ;;
        *) return 0 ;;
    esac
    local base=${candidate##*/}
    if ! detect_files_is_executable_php_name "$base"; then
        return 0
    fi
    if is_allowlisted_path "$candidate"; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_INFO" \
            "confidence=$CONFIDENCE_HEURISTIC" \
            "category=php-in-writable-directory-allowlisted" \
            "title=PHP-bestand in $location, afgedekt door de allowlist" \
            "detail=Dit bestand valt onder een pad in WP2SHELL_ALLOWLIST_PATHS en wordt daarom niet als besmetting behandeld. Het wordt wel vermeld, want een allowlist die te ruim staat verbergt precies wat deze regel moet vinden. Omvang $size bytes." \
            "file=$candidate" \
            "sha1=$WP2SHELL_DETECT_FILES_CURRENT_SHA1" \
            "remediation=Controleer of deze allowlist-regel nog klopt."
        return 0
    fi
    detect_files_note_signal "uitvoerbare PHP in $location"
    WP2SHELL_DETECT_FILES_HIGH_REPORTED=1
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_CRITICAL" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=php-in-writable-directory" \
        "title=Uitvoerbare PHP in $location" \
        "detail=In $location hoort geen PHP te staan. WordPress schrijft daar media en cachebestanden, geen code. Een PHP-bestand op deze plek is de klassieke uitkomst van een upload-webshell en dit signaal is onafhankelijk van naamgeving of versie. Omvang $size bytes." \
        "file=$candidate" \
        "sha1=$WP2SHELL_DETECT_FILES_CURRENT_SHA1" \
        "evidence=$relative" \
        "remediation=Zet dit bestand in quarantaine en blokkeer daarna de uitvoering van PHP in uploads en cache."
    return 0
}

detect_files_report_suspicious_name() {
    local site_path=$1 relative=$2 candidate=$3 size=$4
    local base=${candidate##*/}
    local reason=''
    if ! reason=$(detect_files_suspicious_name_reason "$base"); then
        return 0
    fi
    detect_files_note_signal "verdachte bestandsnaam"
    local size_note=''
    if size_note=$(detect_files_size_profile_label "$size"); then
        detect_files_note_signal "$size_note"
    else
        size_note='omvang komt niet overeen met een van de twee bekende profielen'
    fi
    local location_note=''
    case $relative in
        wp-content/uploads/*) location_note=' Het bestand staat in wp-content/uploads, waar de dropper zijn archief neerzet.' ;;
        wp-content/upgrade/*) location_note=' Het bestand staat in wp-content/upgrade, de map die WordPress bij plugin-installaties gebruikt.' ;;
    esac
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_HIGH" \
        "confidence=$CONFIDENCE_HEURISTIC" \
        "category=suspicious-name" \
        "title=Verdachte bestandsnaam voor de wp2shell-campagne" \
        "detail=De naam $base valt op. Reden: $reason.$location_note Omvang $size bytes, $size_note. Naamgeving is uitsluitend bedoeld om deze site hoger in de handmatige triage te zetten, het is op zichzelf nooit voldoende bewijs, want de aanvaller kiest de naam vrij." \
        "file=$candidate" \
        "sha1=$WP2SHELL_DETECT_FILES_CURRENT_SHA1" \
        "evidence=$base" \
        "remediation=Bekijk de inhoud van dit bestand handmatig voordat er iets verwijderd wordt."
    return 0
}

detect_files_track_plugin_structure() {
    local site_path=$1 relative=$2 candidate=$3 has_open_rest=$4 has_sink=$5 has_decode=$6
    local plugin_dir
    if ! plugin_dir=$(detect_files_plugin_directory_for "$site_path" "$relative"); then
        return 0
    fi
    if [ "$has_open_rest" = "1" ]; then
        WP2SHELL_DETECT_FILES_PLUGIN_OPEN_REST["$plugin_dir"]="$candidate"
        WP2SHELL_DETECT_FILES_PLUGIN_OPEN_REST_EVIDENCE["$plugin_dir"]=$(detect_files_first_match_line "$candidate" 'permission_callback')
    fi
    if [ "$has_sink" = "1" ] && [ "$has_decode" = "1" ]; then
        WP2SHELL_DETECT_FILES_PLUGIN_EXEC_SINK["$plugin_dir"]="$candidate"
        WP2SHELL_DETECT_FILES_PLUGIN_EXEC_SINK_EVIDENCE["$plugin_dir"]=$(detect_files_first_match_line "$candidate" 'base64_decode(')
    fi
    return 0
}

detect_files_report_plugin_structures() {
    local site_path=$1
    if [ "${#WP2SHELL_DETECT_FILES_PLUGIN_OPEN_REST[@]}" -eq 0 ]; then
        return 0
    fi
    local plugin_dir rest_file sink_file rest_evidence sink_evidence plugin_name
    for plugin_dir in "${!WP2SHELL_DETECT_FILES_PLUGIN_OPEN_REST[@]}"; do
        sink_file=${WP2SHELL_DETECT_FILES_PLUGIN_EXEC_SINK["$plugin_dir"]:-}
        if [ -z "$sink_file" ]; then
            continue
        fi
        rest_file=${WP2SHELL_DETECT_FILES_PLUGIN_OPEN_REST["$plugin_dir"]}
        rest_evidence=${WP2SHELL_DETECT_FILES_PLUGIN_OPEN_REST_EVIDENCE["$plugin_dir"]:-}
        sink_evidence=${WP2SHELL_DETECT_FILES_PLUGIN_EXEC_SINK_EVIDENCE["$plugin_dir"]:-}
        plugin_name=${plugin_dir##*/}
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_CRITICAL" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=malicious-plugin-structure" \
            "title=Plugin $plugin_name combineert een open REST-route met een commando-uitvoerder" \
            "detail=In deze pluginmap staat zowel een REST-route waarvan de permission_callback op __return_true staat, dus zonder enige autorisatie bereikbaar, als code die een commando-sink aanroept op base64-gedecodeerde invoer. Die twee samen vormen de structuur van de webshellplugin die na de wp2shell-exploitatie wordt geplaatst. De structuur is beoordeeld en niet de naam, want de gerapporteerde naamgevingen lopen sterk uiteen. Open route in $rest_file, commando-sink in $sink_file." \
            "file=$plugin_dir" \
            "evidence=$rest_evidence | $sink_evidence" \
            "remediation=Deactiveer deze plugin niet via de beheerinterface maar zet de hele map in quarantaine en behandel de installatie als gecompromitteerd."
    done
    return 0
}

detect_files_report_minimal_backdoor() {
    local site_path=$1 candidate=$2 size=$3 literal=$4
    local evidence extra=''
    evidence=$(detect_files_first_match_line "$candidate" "$literal")
    if detect_files_contains_literal "$candidate" 'http_response_code(404' ||
        detect_files_contains_literal "$candidate" '404 Not Found'; then
        extra=' Het bestand geeft daarnaast een 404 terug, een bekende manier om voor een scanner of een beheerder op niets te lijken.'
    fi
    WP2SHELL_DETECT_FILES_HIGH_REPORTED=1
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_CRITICAL" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=minimal-backdoor" \
        "title=Minimale backdoor die invoer uit het verzoek uitvoert" \
        "detail=Dit bestand is $size bytes groot en bestaat in de kern uit het uitvoeren van een parameter uit het verzoek. Legitieme code doet dit niet. De combinatie van de zeer kleine omvang en een eval of assert op een superglobal is op zichzelf al voldoende voor een bevestigde bevinding.$extra" \
        "file=$candidate" \
        "sha1=$WP2SHELL_DETECT_FILES_CURRENT_SHA1" \
        "evidence=$evidence" \
        "remediation=Zet dit bestand in quarantaine en zoek in de toegangslogs naar de verzoeken die het hebben aangeroepen."
    return 0
}

detect_files_scan_file_content() {
    local site_path=$1 relative=$2 candidate=$3 size=$4
    if [ -z "$WP2SHELL_FILE_IOC_PATTERN_FILE" ] || [ ! -s "$WP2SHELL_FILE_IOC_PATTERN_FILE" ]; then
        return 0
    fi
    if ! grep -I -q -m1 -e . -- "$candidate" 2>/dev/null; then
        log_debug "Binair of leeg bestand overgeslagen bij de patrooncontrole: $candidate"
        return 0
    fi
    local matches='' status=0
    matches=$(grep -o -F -f "$WP2SHELL_FILE_IOC_PATTERN_FILE" -- "$candidate" 2>/dev/null | LC_ALL=C sort -u) || status=$?
    if [ "$status" -gt 1 ]; then
        log_warn "Patrooncontrole is mislukt op $candidate"
        return 1
    fi
    if [ -z "$matches" ]; then
        return 0
    fi
    local literal category confidence
    local high_count=0 medium_count=0
    local has_backdoor=0 has_open_rest=0 has_sink=0 has_decode=0 has_namespace=0 has_fake_author=0
    local strongest_literal='' backdoor_literal='' medium_literal=''
    while IFS= read -r literal; do
        if [ -z "$literal" ]; then
            continue
        fi
        category=${WP2SHELL_FILE_IOC_PATTERN_CATEGORY["$literal"]:-onbekend}
        confidence=${WP2SHELL_FILE_IOC_PATTERN_CONFIDENCE["$literal"]:-low}
        detect_files_note_signal "patroon $literal"
        case $confidence in
            high)
                high_count=$((high_count + 1))
                ;;
            medium)
                medium_count=$((medium_count + 1))
                if [ -z "$medium_literal" ]; then
                    medium_literal="$literal"
                fi
                ;;
        esac
        case $category in
            backdoor)
                has_backdoor=1
                if [ -z "$backdoor_literal" ]; then
                    backdoor_literal="$literal"
                fi
                ;;
            unpack) has_decode=1 ;;
            obfuscation) has_decode=1 ;;
            sink) has_sink=1 ;;
            rest-open) has_open_rest=1 ;;
            rest-namespace) has_namespace=1 ;;
            fake-author) has_fake_author=1 ;;
        esac
        if [ "$confidence" = "high" ] && [ -z "$strongest_literal" ]; then
            strongest_literal="$literal"
        fi
    done <<<"$matches"
    if [ "$has_namespace" = "1" ]; then
        WP2SHELL_DETECT_FILES_HIGH_REPORTED=1
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_CRITICAL" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=wp2shell-rest-namespace" \
            "title=REST-namespace morning/v1 aangetroffen" \
            "detail=Dit bestand registreert of gebruikt de REST-namespace morning/v1. Die namespace hoort niet bij WordPress zelf en is bij deze campagne meermaals waargenomen als het kanaal waarlangs commando's binnenkomen." \
            "file=$candidate" \
            "sha1=$WP2SHELL_DETECT_FILES_CURRENT_SHA1" \
            "evidence=$(detect_files_first_match_line "$candidate" 'morning/v1')" \
            "remediation=Zet dit bestand of de bijbehorende pluginmap in quarantaine en behandel de installatie als gecompromitteerd."
        high_count=$((high_count - 1))
    fi
    if [ "$has_fake_author" = "1" ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_HIGH" \
            "confidence=$CONFIDENCE_HEURISTIC" \
            "category=fake-plugin-header" \
            "title=Pluginheader met een vervalste auteur" \
            "detail=Dit bestand voert als auteur de WordPress.org Community op. Die aanduiding bestaat niet bij echte plugins uit de directory en is waargenomen bij de plugins die na wp2shell-exploitatie werden achtergelaten, waarschijnlijk om er in de pluginlijst legitiem uit te zien." \
            "file=$candidate" \
            "sha1=$WP2SHELL_DETECT_FILES_CURRENT_SHA1" \
            "evidence=$(detect_files_first_match_line "$candidate" 'Author: WordPress.org Community')" \
            "remediation=Vergelijk deze plugin met de officiele versie of verwijder hem als hij daar niet voorkomt."
        medium_count=$((medium_count - 1))
    fi
    detect_files_track_plugin_structure "$site_path" "$relative" "$candidate" \
        "$has_open_rest" "$has_sink" "$has_decode"
    if [ "$has_backdoor" = "1" ] && [ "$size" -le "$WP2SHELL_DETECT_FILES_ONELINER_MAX_BYTES" ]; then
        detect_files_report_minimal_backdoor "$site_path" "$candidate" "$size" "$backdoor_literal"
        return 0
    fi
    if [ "$high_count" -gt 0 ]; then
        local confidence_level
        confidence_level=$(detect_files_confidence_for_signal_count)
        if [ "$confidence_level" = "$CONFIDENCE_HIGH" ]; then
            WP2SHELL_DETECT_FILES_HIGH_REPORTED=1
        fi
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_HIGH" \
            "confidence=$confidence_level" \
            "category=backdoor-pattern" \
            "title=Backdoor- of obfuscatiepatroon in PHP-bestand" \
            "detail=Dit bestand bevat een patroon dat op de lijst met sterke indicatoren staat. Aantal getelde signalen: $WP2SHELL_DETECT_FILES_SIGNAL_COUNT. Signalen: $(detect_files_signal_summary). Vanaf twee onafhankelijke signalen wordt dit als bevestigd gerapporteerd, bij een enkel signaal blijft het heuristisch, omdat ook legitieme code deze functies gebruikt." \
            "file=$candidate" \
            "sha1=$WP2SHELL_DETECT_FILES_CURRENT_SHA1" \
            "evidence=$(detect_files_first_match_line "$candidate" "$strongest_literal")" \
            "remediation=Beoordeel dit bestand handmatig, vergelijk het met de originele plugin of core en zet het in quarantaine als het niet klopt."
        return 0
    fi
    if [ "$medium_count" -gt 0 ] && [ "$WP2SHELL_DETECT_FILES_SIGNAL_COUNT" -ge 2 ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HEURISTIC" \
            "category=suspicious-code" \
            "title=Verdachte combinatie van functies in PHP-bestand" \
            "detail=Aantal getelde signalen: $WP2SHELL_DETECT_FILES_SIGNAL_COUNT. Signalen: $(detect_files_signal_summary). Elk signaal afzonderlijk komt ook in legitieme plugins voor, de combinatie verdient handmatige review. Er wordt hier bewust niets als bevestigd gemeld." \
            "file=$candidate" \
            "sha1=$WP2SHELL_DETECT_FILES_CURRENT_SHA1" \
            "evidence=$(detect_files_first_match_line "$candidate" "$medium_literal")" \
            "remediation=Bekijk dit bestand handmatig en vergelijk het met de originele broncode van de plugin of het thema."
    fi
    return 0
}

detect_files_report_htaccess() {
    local site_path=$1 relative=$2 candidate=$3
    local line=''
    if line=$(grep -F -n -m1 -e 'auto_prepend_file' -- "$candidate" 2>/dev/null); then
        local severity="$SEVERITY_HIGH" confidence="$CONFIDENCE_HEURISTIC"
        local extra='Beheerders zetten dit soms zelf in, dus dit wordt heuristisch gerapporteerd.'
        case $line in
            *uploads/*|*cache/*|*/tmp/*|*upgrade/*)
                severity="$SEVERITY_CRITICAL"
                confidence="$CONFIDENCE_HIGH"
                extra='Het voorgeschakelde bestand staat in een map waar alleen uploads, cache of tijdelijke bestanden horen te staan. Dat is geen legitieme configuratie.'
                ;;
        esac
        record_finding \
            "site=$site_path" \
            "severity=$severity" \
            "confidence=$confidence" \
            "category=htaccess-auto-prepend" \
            "title=auto_prepend_file in .htaccess" \
            "detail=Met auto_prepend_file wordt bij elke PHP-aanvraag eerst een ander bestand geladen. Dat is een veelgebruikte manier om een backdoor te laten voortleven ook nadat de webshell zelf is opgeruimd. $extra" \
            "file=$candidate" \
            "evidence=$(detect_files_evidence_snippet "$line")" \
            "remediation=Stel vast welk bestand hier wordt voorgeschakeld, beoordeel dat bestand en verwijder de regel als hij niet van de beheerder komt."
    fi
    case $relative in
        wp-content/*) ;;
        *) return 0 ;;
    esac
    if line=$(grep -E -n -m1 -e '^[[:space:]]*(RewriteRule|Redirect|RedirectMatch)[[:space:]].*https?://' -- "$candidate" 2>/dev/null); then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HEURISTIC" \
            "category=htaccess-redirect" \
            "title=Omleiding in een .htaccess onder wp-content" \
            "detail=Deze .htaccess stuurt bezoekers door naar een volledig uitgeschreven adres. In de siteroot is dat normaal, onder wp-content is het ongebruikelijk en het is de standaardmanier om bezoekers of zoekmachines naar een andere site te sturen." \
            "file=$candidate" \
            "evidence=$(detect_files_evidence_snippet "$line")" \
            "remediation=Controleer waar deze omleiding naartoe wijst en of de beheerder hem zelf heeft aangebracht."
    fi
    if line=$(grep -E -i -n -m1 -e '^[[:space:]]*(AddType|AddHandler|SetHandler)[^[:cntrl:]]*php|^[[:space:]]*php_flag[[:space:]]+engine[[:space:]]+on' -- "$candidate" 2>/dev/null); then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_HIGH" \
            "confidence=$CONFIDENCE_HEURISTIC" \
            "category=htaccess-php-handler" \
            "title=PHP-uitvoering wordt aangezet in een .htaccess onder wp-content" \
            "detail=Deze .htaccess koppelt een handler of type aan PHP. Aanvallers plaatsen zoiets om PHP alsnog te laten draaien in een map waar dat geblokkeerd was. Onder OpenLiteSpeed werken deze directives niet altijd, dus de aanwezigheid zegt niet dat het ook effect heeft." \
            "file=$candidate" \
            "evidence=$(detect_files_evidence_snippet "$line")" \
            "remediation=Verwijder de regel als de beheerder hem niet zelf heeft aangebracht en controleer de map op PHP-bestanden."
    fi
    return 0
}

detect_files_report_user_ini() {
    local site_path=$1 candidate=$2
    local line=''
    if ! line=$(grep -F -n -m1 -e 'auto_prepend_file' -- "$candidate" 2>/dev/null); then
        return 0
    fi
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_HIGH" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=user-ini-auto-prepend" \
        "title=auto_prepend_file in .user.ini" \
        "detail=Een .user.ini met auto_prepend_file laadt bij elke PHP-aanvraag eerst een ander bestand. Anders dan bij .htaccess werkt dit ook onder OpenLiteSpeed en WordPress of zijn plugins schrijven deze instelling niet. Dit is een sterk signaal van persistentie." \
        "file=$candidate" \
        "evidence=$(detect_files_evidence_snippet "$line")" \
        "remediation=Beoordeel het voorgeschakelde bestand, zet het in quarantaine en verwijder deze regel uit .user.ini."
    return 0
}

detect_files_report_wp_config() {
    local site_path=$1 candidate=$2
    if [ "$WP2SHELL_DETECT_FILES_HIGH_REPORTED" = "1" ]; then
        return 0
    fi
    local line=''
    if ! line=$(grep -E -n -m1 -e 'eval[[:space:]]*\(|base64_decode[[:space:]]*\(|(include|require)(_once)?[^;]*(uploads|/cache/|/tmp/|\.ico|\.png|\.jpe?g|\.gif|\.txt)' -- "$candidate" 2>/dev/null); then
        return 0
    fi
    local severity="$SEVERITY_HIGH" confidence="$CONFIDENCE_HEURISTIC"
    case $line in
        *uploads*|*/cache/*|*/tmp/*)
            severity="$SEVERITY_CRITICAL"
            confidence="$CONFIDENCE_HIGH"
            ;;
    esac
    record_finding \
        "site=$site_path" \
        "severity=$severity" \
        "confidence=$confidence" \
        "category=wp-config-modified" \
        "title=wp-config.php bevat code die er niet hoort" \
        "detail=In wp-config.php staat een eval, een base64_decode of een include van een pad dat naar uploads, cache of tijdelijke bestanden wijst. Het originele wp-config.php bevat alleen instellingen en sluit af met wp-settings.php. Alles wat daarvan afwijkt moet verklaard kunnen worden." \
        "file=$candidate" \
        "sha1=$WP2SHELL_DETECT_FILES_CURRENT_SHA1" \
        "evidence=$(detect_files_evidence_snippet "$line")" \
        "remediation=Vergelijk wp-config.php met een backup van voor het blootstellingsvenster en verwijder de toegevoegde regels."
    return 0
}

detect_files_report_root_index() {
    local site_path=$1 candidate=$2 size=$3
    if detect_files_contains_literal "$candidate" 'wp-blog-header.php'; then
        return 0
    fi
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_HIGH" \
        "confidence=$CONFIDENCE_HEURISTIC" \
        "category=modified-index" \
        "title=index.php in de siteroot is niet de standaard WordPress-loader" \
        "detail=De index.php van WordPress laadt wp-blog-header.php en doet verder niets. Dit bestand van $size bytes doet dat niet. Dat kan een bewuste maatwerkconstructie zijn, maar het is ook de plek waar een loader voor een backdoor terechtkomt." \
        "file=$candidate" \
        "sha1=$WP2SHELL_DETECT_FILES_CURRENT_SHA1" \
        "remediation=Vergelijk dit bestand met de index.php uit een schone WordPress van dezelfde versie."
    return 0
}

detect_files_report_configuration_file() {
    local site_path=$1 relative=$2 candidate=$3 size=$4
    local limit=${WP2SHELL_HEURISTIC_MAX_FILE_BYTES:-5242880}
    if [ "$size" -gt "$limit" ] || [ "$size" -eq 0 ]; then
        return 0
    fi
    local base=${candidate##*/}
    case $base in
        .htaccess) detect_files_report_htaccess "$site_path" "$relative" "$candidate" ;;
        .user.ini) detect_files_report_user_ini "$site_path" "$candidate" ;;
    esac
    case $relative in
        wp-config.php) detect_files_report_wp_config "$site_path" "$candidate" ;;
        index.php) detect_files_report_root_index "$site_path" "$candidate" "$size" ;;
    esac
    return 0
}

detect_files_evaluate_file() {
    local site_path=$1 relative=$2 candidate=$3 size=$4
    local base=${candidate##*/}
    local limit=${WP2SHELL_HEURISTIC_MAX_FILE_BYTES:-5242880}
    detect_files_reset_file_state
    local scannable=0
    if detect_files_is_php_candidate "$base" && [ "$size" -gt 0 ] && [ "$size" -le "$limit" ]; then
        scannable=1
    fi
    if [ "$scannable" = "1" ]; then
        detect_files_compute_hashes "$candidate"
    elif detect_files_is_php_candidate "$base"; then
        log_debug "PHP-bestand te groot voor inhoudscontrole, alleen padregels toegepast: $candidate"
    fi
    detect_files_note_location_signals "$relative"
    detect_files_report_clamav_hit "$site_path" "$candidate"
    if [ "$scannable" = "1" ]; then
        detect_files_report_hash_match "$site_path" "$candidate"
    fi
    detect_files_report_mu_plugin_file "$site_path" "$relative" "$candidate"
    detect_files_report_php_in_writable_directory "$site_path" "$relative" "$candidate" "$size"
    detect_files_report_suspicious_name "$site_path" "$relative" "$candidate" "$size"
    if [ "$scannable" = "1" ]; then
        detect_files_scan_file_content "$site_path" "$relative" "$candidate" "$size" || return 1
    fi
    detect_files_report_configuration_file "$site_path" "$relative" "$candidate" "$size"
    return 0
}

detect_files_evaluate_candidates() {
    local site_path=$1 listing=$2
    local size candidate relative examined=0
    while IFS= read -r -d '' size && IFS= read -r -d '' candidate; do
        case $size in
            ''|*[!0-9]*) size=0 ;;
        esac
        relative=${candidate#"$site_path"/}
        examined=$((examined + 1))
        detect_files_evaluate_file "$site_path" "$relative" "$candidate" "$size" ||
            log_warn "Bestand kon niet volledig beoordeeld worden: $candidate"
    done < "$listing"
    log_debug "$examined kandidaatbestanden beoordeeld in $site_path"
    return 0
}

detect_files_report_suspicious_directories() {
    local site_path=$1
    local listing status base entry name reason
    listing=$(mktemp -t wp2shell-dirs.XXXXXXXX) || return 1
    register_temp_cleanup "$listing"
    for base in \
        "$site_path/wp-content/plugins" \
        "$site_path/wp-content/mu-plugins" \
        "$site_path/wp-content/upgrade" \
        "$site_path/wp-content/uploads"
    do
        if [ ! -d "$base" ]; then
            continue
        fi
        status=0
        find -P "$base" -mindepth 1 -maxdepth 1 -type d -print0 > "$listing" 2>/dev/null || status=$?
        if [ "$status" -ne 0 ]; then
            log_warn "Kon $base niet volledig uitlezen, exitcode $status"
        fi
        while IFS= read -r -d '' entry; do
            name=${entry##*/}
            if ! reason=$(detect_files_suspicious_name_reason "$name"); then
                continue
            fi
            record_finding \
                "site=$site_path" \
                "severity=$SEVERITY_HIGH" \
                "confidence=$CONFIDENCE_HEURISTIC" \
                "category=suspicious-plugin-name" \
                "title=Verdachte mapnaam $name" \
                "detail=De map $entry valt op. Reden: $reason. Naamgeving is alleen bedoeld voor de volgorde van handmatige triage. De leveranciers melden sterk uiteenlopende namen, dus een verdachte naam bewijst niets en een gewone naam pleit niet vrij." \
                "file=$entry" \
                "evidence=$name" \
                "remediation=Controleer of deze map bij een plugin hoort die de beheerder zelf heeft geinstalleerd."
        done < "$listing"
    done
    rm -f -- "$listing"
    return 0
}

detect_files_for_site() {
    local site_path=${1:-}
    local owner_user=${2:-}
    if [ -z "$site_path" ]; then
        log_error "detect_files_for_site is aangeroepen zonder sitepad"
        return "$EXIT_INTERNAL"
    fi
    site_path=${site_path%/}
    if [ ! -d "$site_path" ]; then
        log_error "Sitepad bestaat niet of is geen map: $site_path"
        return "$EXIT_INTERNAL"
    fi
    load_file_iocs || true
    detect_files_report_ioc_gap "$site_path"
    WP2SHELL_DETECT_FILES_PLUGIN_OPEN_REST=()
    WP2SHELL_DETECT_FILES_PLUGIN_OPEN_REST_EVIDENCE=()
    WP2SHELL_DETECT_FILES_PLUGIN_EXEC_SINK=()
    WP2SHELL_DETECT_FILES_PLUGIN_EXEC_SINK_EVIDENCE=()
    WP2SHELL_DETECT_FILES_CLAMAV_HITS=()
    local listing status=0
    listing=$(mktemp -t wp2shell-candidates.XXXXXXXX) || {
        log_error "Kan geen tijdelijk bestand aanmaken voor de bestandsscan van $site_path"
        return "$EXIT_INTERNAL"
    }
    register_temp_cleanup "$listing"
    log_debug "Bestandsscan gestart voor $site_path"
    detect_files_collect_candidates "$site_path" "$listing" || status=$?
    if [ "$status" -ne 0 ]; then
        log_warn "Het doorlopen van $site_path gaf exitcode $status"
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=scan-incomplete" \
            "title=De bestandsscan van deze installatie is mogelijk onvolledig" \
            "detail=Tijdens het doorlopen van de mappen van deze installatie waren niet alle paden leesbaar. Er kunnen bestanden gemist zijn, dus het uitblijven van bevindingen betekent hier niet dat de installatie schoon is." \
            "remediation=Draai de scan als root en controleer de rechten op de mappen van deze installatie."
    fi
    detect_files_run_clamav_corroboration "$listing" "$owner_user" || \
        log_warn "ClamAV-controle kon niet uitgevoerd worden voor $site_path"
    detect_files_evaluate_candidates "$site_path" "$listing"
    detect_files_report_plugin_structures "$site_path"
    detect_files_report_suspicious_directories "$site_path" || \
        log_warn "Controle op verdachte mapnamen is niet voltooid voor $site_path"
    rm -f -- "$listing"
    return 0
}
