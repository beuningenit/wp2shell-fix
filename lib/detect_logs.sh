WP2SHELL_DETECT_LOGS_LOADED=1

WP2SHELL_DETECT_LOGS_MODULE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd) || WP2SHELL_DETECT_LOGS_MODULE_DIR=""

WP2SHELL_LOG_PATTERN_CATEGORY=()
WP2SHELL_LOG_PATTERN_TIER=()
WP2SHELL_LOG_PATTERN_LITERAL=()
WP2SHELL_LOG_IP_ADDRESS=()
WP2SHELL_LOG_IP_TIER=()
WP2SHELL_LOG_IP_DESCRIPTION=()
WP2SHELL_LOG_IOCS_READY=0

WP2SHELL_LOG_DIRECTORY_LIST=()
WP2SHELL_LOG_READER_COMMAND=()
WP2SHELL_LOG_SOURCES_READ=()
WP2SHELL_LOG_SOURCES_FAILED=()
WP2SHELL_LOG_SOURCES_TRUNCATED=()
WP2SHELL_LOG_DIRECTORIES_PROBED=()
WP2SHELL_LOG_GROUP_KEYS=()
WP2SHELL_LOG_WORK_DIR=""
WP2SHELL_LOG_CATEGORY_PREFIX="log"
WP2SHELL_LOG_FILES_SCANNED=0
WP2SHELL_LOG_COLLECTION_INCOMPLETE=0
WP2SHELL_LOG_SITE_VERSION=""
WP2SHELL_LOG_SITE_STATUS="unknown"
WP2SHELL_LOG_PARAMETER_VALUE=""
WP2SHELL_LOG_TIER_RANK=0
WP2SHELL_LOG_BATCH_KEY=""
WP2SHELL_LOG_ENTRY_ADDRESS=""
WP2SHELL_LOG_ENTRY_TIER=""
WP2SHELL_LOG_ENTRY_DESCRIPTION=""

declare -gA WP2SHELL_LOG_IP_SUPPRESSED=()
declare -gA WP2SHELL_LOG_GROUP_COUNT=()
declare -gA WP2SHELL_LOG_GROUP_FIRST_SEEN=()
declare -gA WP2SHELL_LOG_GROUP_LAST_SEEN=()
declare -gA WP2SHELL_LOG_GROUP_EVIDENCE=()
declare -gA WP2SHELL_LOG_GROUP_SOURCE=()
declare -gA WP2SHELL_LOG_GROUP_STATUSES=()
declare -gA WP2SHELL_LOG_GROUP_SAMPLE=()
declare -gA WP2SHELL_LOG_GROUP_LABEL=()

WP2SHELL_LOG_STATUS_REGEX='"[[:space:]]+([0-9]{3})([[:space:]]|$)'
WP2SHELL_LOG_STATUS_TAIL_REGEX='"[[:space:]]+([0-9]{3})[[:space:]]+([0-9]+|-)([[:space:]]|$)'

detect_logs_extract_status() {
    local line=$1
    local candidate='' position=0
    local remainder="$line"
    while [[ $remainder =~ $WP2SHELL_LOG_STATUS_TAIL_REGEX ]]; do
        candidate=${BASH_REMATCH[1]}
        position=${#BASH_REMATCH[0]}
        remainder=${remainder:$position}
    done
    if [ -n "$candidate" ]; then
        printf '%s' "$candidate"
        return 0
    fi
    remainder="$line"
    while [[ $remainder =~ $WP2SHELL_LOG_STATUS_REGEX ]]; do
        candidate=${BASH_REMATCH[1]}
        position=${#BASH_REMATCH[0]}
        remainder=${remainder:$position}
    done
    printf '%s' "$candidate"
    return 0
}
WP2SHELL_LOG_TIMESTAMP_REGEX='\[([^]]+)\]'
WP2SHELL_LOG_INTEGER_LIST_REGEX='^[0-9]+(,[0-9]+)*$'
WP2SHELL_LOG_ROTATION_REGEX='^[.-]([0-9]{1,10}|[0-9]{4}-[0-9]{2}-[0-9]{2}|[0-9]{8}-[0-9]{6})$'

detect_logs_ioc_directory() {
    local candidate
    for candidate in \
        "${WP2SHELL_IOC_DIR:-}" \
        "${WP2SHELL_ROOT:-}/config/iocs" \
        "$WP2SHELL_DETECT_LOGS_MODULE_DIR/../config/iocs"
    do
        if [ -n "$candidate" ] && [ -d "$candidate" ]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

detect_logs_set_tier_rank() {
    case $1 in
        high) WP2SHELL_LOG_TIER_RANK=3 ;;
        medium) WP2SHELL_LOG_TIER_RANK=2 ;;
        low) WP2SHELL_LOG_TIER_RANK=1 ;;
        *) WP2SHELL_LOG_TIER_RANK=0 ;;
    esac
    return 0
}

detect_logs_tier_severity() {
    case $1 in
        high) printf '%s' "$SEVERITY_MEDIUM" ;;
        medium) printf '%s' "$SEVERITY_LOW" ;;
        *) printf '%s' "$SEVERITY_INFO" ;;
    esac
}

detect_logs_tier_confidence() {
    case $1 in
        high) printf '%s' "$CONFIDENCE_HIGH" ;;
        *) printf '%s' "$CONFIDENCE_HEURISTIC" ;;
    esac
}

detect_logs_pattern_is_known() {
    local literal=$1 index total
    total=${#WP2SHELL_LOG_PATTERN_LITERAL[@]}
    for ((index = 0; index < total; index++)); do
        if [ "${WP2SHELL_LOG_PATTERN_LITERAL[index]}" = "$literal" ]; then
            return 0
        fi
    done
    return 1
}

detect_logs_add_pattern() {
    local category=$1 tier=$2 literal=$3
    local lowered=${literal,,}
    if [ -z "$lowered" ]; then
        return 0
    fi
    if detect_logs_pattern_is_known "$lowered"; then
        return 0
    fi
    WP2SHELL_LOG_PATTERN_CATEGORY+=("$category")
    WP2SHELL_LOG_PATTERN_TIER+=("$tier")
    WP2SHELL_LOG_PATTERN_LITERAL+=("$lowered")
    return 0
}

detect_logs_add_pattern_with_mangled_variants() {
    local category=$1 tier=$2 literal=$3
    detect_logs_add_pattern "$category" "$tier" "$literal"
    if [ "$category" != "sqli" ]; then
        return 0
    fi
    detect_logs_add_pattern "$category" "$tier" "${literal//_/.}"
    detect_logs_add_pattern "$category" "$tier" "${literal//_/ }"
    detect_logs_add_pattern "$category" "$tier" "${literal//_/%20}"
    detect_logs_add_pattern "$category" "$tier" "${literal//./_}"
    return 0
}

detect_logs_split_indicator_entry() {
    local entry=$1 tier
    WP2SHELL_LOG_ENTRY_ADDRESS=""
    WP2SHELL_LOG_ENTRY_TIER=""
    WP2SHELL_LOG_ENTRY_DESCRIPTION=""
    for tier in high medium low; do
        case $entry in
            *":$tier:"*)
                WP2SHELL_LOG_ENTRY_ADDRESS=${entry%%":$tier:"*}
                WP2SHELL_LOG_ENTRY_TIER=$tier
                WP2SHELL_LOG_ENTRY_DESCRIPTION=${entry#*":$tier:"}
                ;;
        esac
        if [ -n "$WP2SHELL_LOG_ENTRY_TIER" ]; then
            break
        fi
    done
    if [ -z "$WP2SHELL_LOG_ENTRY_TIER" ]; then
        return 1
    fi
    WP2SHELL_LOG_ENTRY_ADDRESS=${WP2SHELL_LOG_ENTRY_ADDRESS#[}
    WP2SHELL_LOG_ENTRY_ADDRESS=${WP2SHELL_LOG_ENTRY_ADDRESS%]}
    if [ -z "$WP2SHELL_LOG_ENTRY_ADDRESS" ]; then
        return 1
    fi
    return 0
}

detect_logs_load_ip_denylist() {
    local ioc_dir=$1
    local denylist="$ioc_dir/ip-denylist.txt"
    WP2SHELL_LOG_IP_SUPPRESSED=()
    if [ ! -r "$denylist" ]; then
        log_debug "Geen ip-denylist gevonden op $denylist"
        return 0
    fi
    local line address reason
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%%$'\r'}
        case $line in
            ''|'#'*) continue ;;
        esac
        case $line in
            '['*)
                address=${line%%]*}
                address=${address#[}
                reason=${line#*]:}
                ;;
            *)
                address=${line%%:*}
                reason=${line#*:}
                ;;
        esac
        if [ -z "$address" ]; then
            continue
        fi
        WP2SHELL_LOG_IP_SUPPRESSED["${address,,}"]=$reason
        log_debug "IP-indicator onderdrukt door denylist: $address"
    done < "$denylist"
    return 0
}

detect_logs_load_ip_indicators() {
    local ioc_dir=$1
    local indicators="$ioc_dir/ips.txt"
    WP2SHELL_LOG_IP_ADDRESS=()
    WP2SHELL_LOG_IP_TIER=()
    WP2SHELL_LOG_IP_DESCRIPTION=()
    if [ ! -r "$indicators" ]; then
        log_warn "Geen IP-indicatoren gevonden op $indicators"
        return 0
    fi
    local line address
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%%$'\r'}
        case $line in
            ''|'#'*) continue ;;
        esac
        if ! detect_logs_split_indicator_entry "$line"; then
            log_warn "Onbruikbare regel in $indicators overgeslagen"
            continue
        fi
        address=${WP2SHELL_LOG_ENTRY_ADDRESS,,}
        if [ -n "${WP2SHELL_LOG_IP_SUPPRESSED["$address"]:-}" ]; then
            log_info "IP $address staat op de denylist en levert geen bevinding op: ${WP2SHELL_LOG_IP_SUPPRESSED["$address"]}"
            continue
        fi
        WP2SHELL_LOG_IP_ADDRESS+=("$address")
        WP2SHELL_LOG_IP_TIER+=("$WP2SHELL_LOG_ENTRY_TIER")
        WP2SHELL_LOG_IP_DESCRIPTION+=("$WP2SHELL_LOG_ENTRY_DESCRIPTION")
    done < "$indicators"
    return 0
}

detect_logs_load_log_patterns() {
    local ioc_dir=$1
    local patterns="$ioc_dir/log-patterns.txt"
    WP2SHELL_LOG_PATTERN_CATEGORY=()
    WP2SHELL_LOG_PATTERN_TIER=()
    WP2SHELL_LOG_PATTERN_LITERAL=()
    if [ ! -r "$patterns" ]; then
        log_error "Logpatronen niet leesbaar: $patterns"
        return 1
    fi
    local line category remainder tier literal
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%%$'\r'}
        case $line in
            ''|'#'*) continue ;;
        esac
        category=${line%%:*}
        remainder=${line#*:}
        tier=${remainder%%:*}
        literal=${remainder#*:}
        if [ -z "$category" ] || [ -z "$literal" ] || [ "$literal" = "$remainder" ]; then
            log_warn "Onbruikbare regel in $patterns overgeslagen"
            continue
        fi
        case $tier in
            high|medium|low) ;;
            *)
                log_warn "Onbekend niveau $tier in $patterns, regel overgeslagen"
                continue
                ;;
        esac
        detect_logs_add_pattern_with_mangled_variants "$category" "$tier" "$literal"
    done < "$patterns"
    if [ "${#WP2SHELL_LOG_PATTERN_LITERAL[@]}" -eq 0 ]; then
        log_error "Geen bruikbare logpatronen geladen uit $patterns"
        return 1
    fi
    return 0
}

detect_logs_load_iocs() {
    if [ "$WP2SHELL_LOG_IOCS_READY" = "1" ]; then
        return 0
    fi
    local ioc_dir
    if ! ioc_dir=$(detect_logs_ioc_directory); then
        log_error "IOC-map niet gevonden, loganalyse kan geen patronen laden"
        return 1
    fi
    if ! detect_logs_load_log_patterns "$ioc_dir"; then
        return 1
    fi
    detect_logs_load_ip_denylist "$ioc_dir"
    detect_logs_load_ip_indicators "$ioc_dir"
    WP2SHELL_LOG_IOCS_READY=1
    log_debug "Loganalyse geladen met ${#WP2SHELL_LOG_PATTERN_LITERAL[@]} patronen en ${#WP2SHELL_LOG_IP_ADDRESS[@]} IP-indicatoren"
    return 0
}

detect_logs_write_grep_patterns() {
    local destination=$1
    local scope=${2:-all}
    local index total
    : > "$destination"
    if [ "$scope" = "all" ] || [ "$scope" = "signatures" ]; then
        total=${#WP2SHELL_LOG_PATTERN_LITERAL[@]}
        for ((index = 0; index < total; index++)); do
            printf '%s\n' "${WP2SHELL_LOG_PATTERN_LITERAL[index]}" >> "$destination"
        done
    fi
    if [ "$scope" = "all" ] || [ "$scope" = "addresses" ]; then
        total=${#WP2SHELL_LOG_IP_ADDRESS[@]}
        for ((index = 0; index < total; index++)); do
            printf '%s\n' "${WP2SHELL_LOG_IP_ADDRESS[index]}" >> "$destination"
        done
    fi
    if [ ! -s "$destination" ]; then
        return 1
    fi
    return 0
}

detect_logs_reader_command() {
    local path=$1
    local lowered=${path,,}
    WP2SHELL_LOG_READER_COMMAND=()
    case $lowered in
        *.gz)
            if have_command zcat; then
                WP2SHELL_LOG_READER_COMMAND=(zcat)
            elif have_command gzip; then
                WP2SHELL_LOG_READER_COMMAND=(gzip -cd)
            fi
            ;;
        *.bz2)
            if have_command bzcat; then
                WP2SHELL_LOG_READER_COMMAND=(bzcat)
            elif have_command bzip2; then
                WP2SHELL_LOG_READER_COMMAND=(bzip2 -cd)
            fi
            ;;
        *.xz)
            if have_command xzcat; then
                WP2SHELL_LOG_READER_COMMAND=(xzcat)
            elif have_command xz; then
                WP2SHELL_LOG_READER_COMMAND=(xz -cd)
            fi
            ;;
        *.zst)
            if have_command zstdcat; then
                WP2SHELL_LOG_READER_COMMAND=(zstdcat)
            elif have_command zstd; then
                WP2SHELL_LOG_READER_COMMAND=(zstd -dcq)
            fi
            ;;
        *.z)
            if have_command zcat; then
                WP2SHELL_LOG_READER_COMMAND=(zcat)
            elif have_command uncompress; then
                WP2SHELL_LOG_READER_COMMAND=(uncompress -c)
            fi
            ;;
        *)
            WP2SHELL_LOG_READER_COMMAND=(cat --)
            ;;
    esac
    if [ "${#WP2SHELL_LOG_READER_COMMAND[@]}" -eq 0 ]; then
        return 1
    fi
    return 0
}

detect_logs_rotation_suffix_is_known() {
    local suffix=$1
    case $suffix in
        .gz|.bz2|.xz|.zst|.Z|.z) return 0 ;;
    esac
    local stem=$suffix
    case $stem in
        *.gz) stem=${stem%.gz} ;;
        *.bz2) stem=${stem%.bz2} ;;
        *.xz) stem=${stem%.xz} ;;
        *.zst) stem=${stem%.zst} ;;
        *.Z) stem=${stem%.Z} ;;
        *.z) stem=${stem%.z} ;;
    esac
    if [[ $stem =~ $WP2SHELL_LOG_ROTATION_REGEX ]]; then
        return 0
    fi
    return 1
}

detect_logs_basename_matches_stem() {
    local base=$1 stem=$2
    if [ "$base" = "$stem" ]; then
        return 0
    fi
    if [ "${WP2SHELL_LOG_SCAN_INCLUDE_ROTATED:-1}" != "1" ]; then
        return 1
    fi
    case $base in
        "$stem"*) ;;
        *) return 1 ;;
    esac
    local suffix=${base#"$stem"}
    detect_logs_rotation_suffix_is_known "$suffix"
}

detect_logs_path_matches_domain() {
    local path=$1 domain=$2
    if [ -z "$domain" ]; then
        return 1
    fi
    local base parent stem
    base=${path##*/}
    parent=${path%/*}
    parent=${parent##*/}
    local -a stems=("$domain.log" "$domain.error.log" "$domain.access.log")
    if [ "$parent" = "$domain" ]; then
        stems+=("access.log" "error.log" "access_log" "error_log")
    fi
    for stem in "${stems[@]}"; do
        if detect_logs_basename_matches_stem "$base" "$stem"; then
            return 0
        fi
    done
    return 1
}

detect_logs_directory_candidates() {
    WP2SHELL_LOG_DIRECTORY_LIST=()
    if [ -n "${WP2SHELL_LOG_DIR_CANDIDATES+set}" ]; then
        WP2SHELL_LOG_DIRECTORY_LIST=("${WP2SHELL_LOG_DIR_CANDIDATES[@]}")
    fi
    if [ "${#WP2SHELL_LOG_DIRECTORY_LIST[@]}" -eq 0 ]; then
        WP2SHELL_LOG_DIRECTORY_LIST=(/var/log/httpd/domains /usr/local/lsws/logs /var/log/litespeed)
        log_debug "Geen logmappen geconfigureerd, standaardkandidaten worden geprobeerd"
    fi
    return 0
}

detect_logs_record_candidate() {
    local path=$1 unsorted=$2 epoch
    epoch=$(stat -c '%Y' -- "$path" 2>/dev/null) || epoch=0
    case $epoch in
        ''|*[!0-9]*) epoch=0 ;;
    esac
    printf '%s\t%s\0' "$epoch" "$path" >> "$unsorted"
    return 0
}

detect_logs_sort_candidates() {
    local unsorted=$1 destination=$2
    : > "$destination"
    if [ ! -s "$unsorted" ]; then
        return 0
    fi
    local sorted="$WP2SHELL_LOG_WORK_DIR/candidates.sorted"
    if ! sort -z -k1,1n "$unsorted" > "$sorted" 2>/dev/null; then
        cat -- "$unsorted" > "$sorted"
    fi
    local record tab=$'\t'
    while IFS= read -r -d '' record; do
        printf '%s\0' "${record#*"$tab"}" >> "$destination"
    done < "$sorted"
    return 0
}

detect_logs_scan_directory_for() {
    local directory=$1 domain=$2 unsorted=$3
    if [ ! -d "$directory" ]; then
        WP2SHELL_LOG_DIRECTORIES_PROBED+=("$directory: niet aanwezig")
        return 0
    fi
    if [ ! -r "$directory" ] || [ ! -x "$directory" ]; then
        WP2SHELL_LOG_DIRECTORIES_PROBED+=("$directory: niet leesbaar voor deze gebruiker")
        WP2SHELL_LOG_COLLECTION_INCOMPLETE=1
        return 0
    fi
    WP2SHELL_LOG_DIRECTORIES_PROBED+=("$directory: doorzocht")
    local listing="$WP2SHELL_LOG_WORK_DIR/listing"
    local status=0 path
    find -P "$directory" -maxdepth 2 -type f -print0 > "$listing" 2>/dev/null || status=$?
    if [ "$status" -ne 0 ]; then
        WP2SHELL_LOG_COLLECTION_INCOMPLETE=1
        WP2SHELL_LOG_SOURCES_FAILED+=("$directory: find gaf exitcode $status")
    fi
    while IFS= read -r -d '' path; do
        if detect_logs_path_matches_domain "$path" "$domain"; then
            detect_logs_record_candidate "$path" "$unsorted"
        fi
    done < "$listing"
    return 0
}

detect_logs_collect_domain_files() {
    local domain=$1 destination=$2
    local unsorted="$WP2SHELL_LOG_WORK_DIR/candidates.raw"
    : > "$unsorted"
    : > "$destination"
    if [ -z "$domain" ]; then
        return 0
    fi
    detect_logs_directory_candidates
    local directory
    for directory in "${WP2SHELL_LOG_DIRECTORY_LIST[@]}"; do
        detect_logs_scan_directory_for "$directory" "$domain" "$unsorted"
    done
    detect_logs_sort_candidates "$unsorted" "$destination"
    return 0
}

detect_logs_collect_server_files() {
    local destination=$1
    local unsorted="$WP2SHELL_LOG_WORK_DIR/candidates.raw"
    : > "$unsorted"
    : > "$destination"
    local -a server_candidates=()
    if [ -n "${WP2SHELL_SERVER_LOG_CANDIDATES+set}" ]; then
        server_candidates=("${WP2SHELL_SERVER_LOG_CANDIDATES[@]}")
    fi
    if [ "${#server_candidates[@]}" -eq 0 ]; then
        server_candidates=(/usr/local/lsws/logs/access.log /usr/local/lsws/logs/error.log)
        log_debug "Geen serverlogs geconfigureerd, standaardkandidaten worden geprobeerd"
    fi
    local candidate directory stem listing status path
    listing="$WP2SHELL_LOG_WORK_DIR/listing"
    for candidate in "${server_candidates[@]}"; do
        directory=${candidate%/*}
        stem=${candidate##*/}
        if [ -z "$directory" ] || [ "$directory" = "$candidate" ]; then
            WP2SHELL_LOG_DIRECTORIES_PROBED+=("$candidate: geen absoluut pad, overgeslagen")
            continue
        fi
        if [ ! -d "$directory" ]; then
            WP2SHELL_LOG_DIRECTORIES_PROBED+=("$directory: niet aanwezig")
            continue
        fi
        if [ ! -r "$directory" ] || [ ! -x "$directory" ]; then
            WP2SHELL_LOG_DIRECTORIES_PROBED+=("$directory: niet leesbaar voor deze gebruiker")
            WP2SHELL_LOG_COLLECTION_INCOMPLETE=1
            continue
        fi
        WP2SHELL_LOG_DIRECTORIES_PROBED+=("$directory: doorzocht op $stem")
        status=0
        find -P "$directory" -maxdepth 1 -type f -print0 > "$listing" 2>/dev/null || status=$?
        if [ "$status" -ne 0 ]; then
            WP2SHELL_LOG_COLLECTION_INCOMPLETE=1
            WP2SHELL_LOG_SOURCES_FAILED+=("$directory: find gaf exitcode $status")
        fi
        while IFS= read -r -d '' path; do
            if detect_logs_basename_matches_stem "${path##*/}" "$stem"; then
                detect_logs_record_candidate "$path" "$unsorted"
            fi
        done < "$listing"
    done
    detect_logs_sort_candidates "$unsorted" "$destination"
    return 0
}

detect_logs_reset_state() {
    WP2SHELL_LOG_SOURCES_READ=()
    WP2SHELL_LOG_SOURCES_FAILED=()
    WP2SHELL_LOG_SOURCES_TRUNCATED=()
    WP2SHELL_LOG_DIRECTORIES_PROBED=()
    WP2SHELL_LOG_GROUP_KEYS=()
    WP2SHELL_LOG_GROUP_COUNT=()
    WP2SHELL_LOG_GROUP_FIRST_SEEN=()
    WP2SHELL_LOG_GROUP_LAST_SEEN=()
    WP2SHELL_LOG_GROUP_EVIDENCE=()
    WP2SHELL_LOG_GROUP_SOURCE=()
    WP2SHELL_LOG_GROUP_STATUSES=()
    WP2SHELL_LOG_GROUP_SAMPLE=()
    WP2SHELL_LOG_GROUP_LABEL=()
    WP2SHELL_LOG_FILES_SCANNED=0
    WP2SHELL_LOG_COLLECTION_INCOMPLETE=0
    return 0
}

detect_logs_readable_text() {
    local raw=$1 converted='' status=0
    if [ -z "$raw" ]; then
        printf ''
        return 0
    fi
    if [ "${WP2SHELL_HAS_ICONV:-0}" = "1" ]; then
        converted=$(printf '%s.' "$raw" | iconv -f UTF-8 -t UTF-8 -c 2>/dev/null) || status=$?
        if [ -n "$converted" ]; then
            printf '%s' "${converted%.}"
            return 0
        fi
        log_debug "iconv leverde geen bruikbare tekst op, exitcode $status, terugval op de ingebouwde filter"
    fi
    printf '%s' "${raw//[![:print:][:space:]]/}"
    return 0
}

detect_logs_group_add() {
    local key=$1 timestamp=$2 evidence=$3 source_file=$4 status=$5 sample=$6
    local current limit
    current=${WP2SHELL_LOG_GROUP_COUNT["$key"]:-0}
    limit=${WP2SHELL_HEURISTIC_EVIDENCE_CHARS:-200}
    case $limit in
        ''|*[!0-9]*) limit=200 ;;
    esac
    if [ "$current" -eq 0 ]; then
        WP2SHELL_LOG_GROUP_KEYS+=("$key")
        WP2SHELL_LOG_GROUP_EVIDENCE["$key"]=$(detect_logs_readable_text "${evidence:0:limit}")
        WP2SHELL_LOG_GROUP_SOURCE["$key"]=$source_file
        WP2SHELL_LOG_GROUP_STATUSES["$key"]=""
        WP2SHELL_LOG_GROUP_SAMPLE["$key"]=""
    fi
    WP2SHELL_LOG_GROUP_COUNT["$key"]=$((current + 1))
    if [ -n "$timestamp" ]; then
        if [ -z "${WP2SHELL_LOG_GROUP_FIRST_SEEN["$key"]:-}" ]; then
            WP2SHELL_LOG_GROUP_FIRST_SEEN["$key"]=$timestamp
        fi
        WP2SHELL_LOG_GROUP_LAST_SEEN["$key"]=$timestamp
    fi
    if [ -n "$status" ]; then
        case " ${WP2SHELL_LOG_GROUP_STATUSES["$key"]} " in
            *" $status "*) ;;
            *) WP2SHELL_LOG_GROUP_STATUSES["$key"]="${WP2SHELL_LOG_GROUP_STATUSES["$key"]} $status" ;;
        esac
    fi
    if [ -n "$sample" ] && [ -z "${WP2SHELL_LOG_GROUP_SAMPLE["$key"]}" ]; then
        WP2SHELL_LOG_GROUP_SAMPLE["$key"]=$(detect_logs_readable_text "${sample:0:limit}")
    fi
    return 0
}

detect_logs_value_is_integer_list() {
    local value=$1
    local normalized=${value//%2c/,}
    if [[ $normalized =~ $WP2SHELL_LOG_INTEGER_LIST_REGEX ]]; then
        return 0
    fi
    return 1
}

detect_logs_extract_parameter_value() {
    local line=$1 key=$2 remainder
    WP2SHELL_LOG_PARAMETER_VALUE=""
    case $line in
        *"$key"*) remainder=${line#*"$key"} ;;
        *) return 1 ;;
    esac
    case $remainder in
        '[]'*) remainder=${remainder#'[]'} ;;
        '%5b%5d'*) remainder=${remainder#'%5b%5d'} ;;
    esac
    case $remainder in
        '='*) remainder=${remainder#=} ;;
        *) return 1 ;;
    esac
    remainder=${remainder%%&*}
    remainder=${remainder%%"%26"*}
    remainder=${remainder%% *}
    remainder=${remainder%%\"*}
    WP2SHELL_LOG_PARAMETER_VALUE=$remainder
    return 0
}

detect_logs_set_batch_group_key() {
    local rank=$1 status=$2
    if [ "$rank" -lt 3 ]; then
        if [ "$rank" -eq 2 ]; then
            WP2SHELL_LOG_BATCH_KEY='batch|weak-medium'
        else
            WP2SHELL_LOG_BATCH_KEY='batch|weak-low'
        fi
        return 0
    fi
    case $status in
        207) WP2SHELL_LOG_BATCH_KEY='batch|207' ;;
        200) WP2SHELL_LOG_BATCH_KEY='batch|200' ;;
        2*) WP2SHELL_LOG_BATCH_KEY='batch|other' ;;
        4*) WP2SHELL_LOG_BATCH_KEY='batch|probe' ;;
        5*) WP2SHELL_LOG_BATCH_KEY='batch|error' ;;
        '') WP2SHELL_LOG_BATCH_KEY='batch|unknown' ;;
        *) WP2SHELL_LOG_BATCH_KEY='batch|other' ;;
    esac
    return 0
}

detect_logs_classify_line() {
    local line=$1 source_file=$2
    local limit=${WP2SHELL_LOG_LINE_MAX_CHARS:-8192}
    case $limit in
        ''|*[!0-9]*) limit=8192 ;;
    esac
    local working=${line:0:limit}
    local lowered=${working,,}
    local squeezed=$lowered
    while [[ $squeezed == *//* ]]; do
        squeezed=${squeezed//\/\//\/}
    done
    local status='' timestamp=''
    status=$(detect_logs_extract_status "$working")
    if [[ $working =~ $WP2SHELL_LOG_TIMESTAMP_REGEX ]]; then
        timestamp=${BASH_REMATCH[1]}
        timestamp=${timestamp//[^0-9A-Za-z:+ ,.\/-]/}
        timestamp=${timestamp:0:48}
    fi
    local index total category tier literal
    local batch_rank=0 lfi_seen=0
    total=${#WP2SHELL_LOG_PATTERN_LITERAL[@]}
    for ((index = 0; index < total; index++)); do
        literal=${WP2SHELL_LOG_PATTERN_LITERAL[index]}
        case $lowered in
            *"$literal"*) ;;
            *)
                case $squeezed in
                    *"$literal"*) ;;
                    *) continue ;;
                esac
                ;;
        esac
        category=${WP2SHELL_LOG_PATTERN_CATEGORY[index]}
        tier=${WP2SHELL_LOG_PATTERN_TIER[index]}
        case $category in
            batch-endpoint)
                detect_logs_set_tier_rank "$tier"
                if [ "$WP2SHELL_LOG_TIER_RANK" -gt "$batch_rank" ]; then
                    batch_rank=$WP2SHELL_LOG_TIER_RANK
                fi
                ;;
            sqli)
                if detect_logs_extract_parameter_value "$lowered" "$literal"; then
                    if [ -n "$WP2SHELL_LOG_PARAMETER_VALUE" ] \
                        && ! detect_logs_value_is_integer_list "$WP2SHELL_LOG_PARAMETER_VALUE"; then
                        WP2SHELL_LOG_GROUP_LABEL["sqli|$literal"]=$literal
                        detect_logs_group_add "sqli|$literal" "$timestamp" "$working" \
                            "$source_file" "$status" "$WP2SHELL_LOG_PARAMETER_VALUE"
                    fi
                fi
                ;;
            lfi)
                lfi_seen=1
                ;;
            useragent)
                WP2SHELL_LOG_GROUP_LABEL["useragent|$literal"]=$literal
                detect_logs_group_add "useragent|$literal" "$timestamp" "$working" \
                    "$source_file" "$status" ""
                ;;
            *)
                WP2SHELL_LOG_GROUP_LABEL["pattern|$category|$tier"]=$category
                detect_logs_group_add "pattern|$category|$tier" "$timestamp" "$working" \
                    "$source_file" "$status" ""
                ;;
        esac
    done
    if [ "$lfi_seen" = "1" ]; then
        if [ "$status" = "200" ]; then
            detect_logs_group_add "lfi|success" "$timestamp" "$working" "$source_file" "$status" ""
        else
            detect_logs_group_add "lfi|attempt" "$timestamp" "$working" "$source_file" "$status" ""
        fi
    fi
    if [ "$batch_rank" -gt 0 ]; then
        detect_logs_set_batch_group_key "$batch_rank" "$status"
        detect_logs_group_add "$WP2SHELL_LOG_BATCH_KEY" "$timestamp" "$working" \
            "$source_file" "$status" ""
    fi
    local client=${lowered%% *}
    local address ip_total
    ip_total=${#WP2SHELL_LOG_IP_ADDRESS[@]}
    for ((index = 0; index < ip_total; index++)); do
        address=${WP2SHELL_LOG_IP_ADDRESS[index]}
        if [ "$client" = "$address" ]; then
            WP2SHELL_LOG_GROUP_LABEL["ip|$address|client"]="$index"
            detect_logs_group_add "ip|$address|client" "$timestamp" "$working" "$source_file" "$status" ""
            continue
        fi
        case $lowered in
            *"$address"*)
                WP2SHELL_LOG_GROUP_LABEL["ip|$address|elders"]="$index"
                detect_logs_group_add "ip|$address|elders" "$timestamp" "$working" "$source_file" "$status" ""
                ;;
        esac
    done
    return 0
}

detect_logs_scan_file() {
    local path=$1 pattern_file=$2
    if [ ! -r "$path" ]; then
        WP2SHELL_LOG_SOURCES_FAILED+=("$path: niet leesbaar voor deze gebruiker")
        return 0
    fi
    if ! detect_logs_reader_command "$path"; then
        WP2SHELL_LOG_SOURCES_FAILED+=("$path: geen uitpakprogramma beschikbaar voor dit bestandstype")
        return 0
    fi
    local max_lines=${WP2SHELL_LOG_SCAN_MAX_LINES:-2000000}
    case $max_lines in
        ''|*[!0-9]*|0) max_lines=2000000 ;;
    esac
    local max_matches=${WP2SHELL_LOG_SCAN_MAX_MATCHES:-5000}
    case $max_matches in
        ''|*[!0-9]*|0) max_matches=5000 ;;
    esac
    local matches="$WP2SHELL_LOG_WORK_DIR/matches"
    local -a pipeline_status=()
    if "${WP2SHELL_LOG_READER_COMMAND[@]}" "$path" 2>/dev/null \
        | head -n "$max_lines" \
        | LC_ALL=C grep -a -i -F -m "$max_matches" -f "$pattern_file" > "$matches" 2>/dev/null
    then
        pipeline_status=("${PIPESTATUS[@]}")
    else
        pipeline_status=("${PIPESTATUS[@]}")
    fi
    local reader_status=${pipeline_status[0]:-0}
    local grep_status=${pipeline_status[2]:-0}
    local matched_lines=0
    matched_lines=$(wc -l < "$matches" 2>/dev/null) || matched_lines=0
    matched_lines=${matched_lines//[^0-9]/}
    if [ -z "$matched_lines" ]; then
        matched_lines=0
    fi
    if [ "$grep_status" -gt 1 ]; then
        WP2SHELL_LOG_SOURCES_FAILED+=("$path: grep gaf exitcode $grep_status")
    else
        WP2SHELL_LOG_SOURCES_READ+=("$path")
        WP2SHELL_LOG_FILES_SCANNED=$((WP2SHELL_LOG_FILES_SCANNED + 1))
    fi
    if [ "$matched_lines" -ge "$max_matches" ]; then
        WP2SHELL_LOG_SOURCES_TRUNCATED+=("$path: gestopt na $max_matches treffers")
    elif [ "$reader_status" -ne 0 ]; then
        WP2SHELL_LOG_SOURCES_TRUNCATED+=("$path: stroom onvolledig gelezen, exitcode $reader_status, afgekapt op $max_lines regels of leesfout")
    fi
    local line
    while IFS= read -r line || [ -n "$line" ]; do
        if [ -n "$line" ]; then
            detect_logs_classify_line "$line" "$path"
        fi
    done < "$matches"
    return 0
}

detect_logs_scan_candidates() {
    local list_file=$1 pattern_file=$2
    local path
    while IFS= read -r -d '' path; do
        detect_logs_scan_file "$path" "$pattern_file"
    done < "$list_file"
    return 0
}

detect_logs_resolve_site_version() {
    local site_path=$1
    WP2SHELL_LOG_SITE_VERSION=""
    WP2SHELL_LOG_SITE_STATUS="unknown"
    if [ "${WP2SHELL_VERSION_LOADED:-0}" != "1" ]; then
        return 0
    fi
    if ! WP2SHELL_LOG_SITE_VERSION=$(wp_version_from_disk "$site_path"); then
        WP2SHELL_LOG_SITE_VERSION=""
        return 0
    fi
    WP2SHELL_LOG_SITE_STATUS=$(classify_wp2shell_status "$WP2SHELL_LOG_SITE_VERSION")
    return 0
}

detect_logs_version_carries_batch_route_flaw() {
    case $WP2SHELL_LOG_SITE_STATUS in
        rce-vulnerable|unknown|'') return 0 ;;
    esac
    return 1
}

detect_logs_version_sentence() {
    if [ "$WP2SHELL_LOG_CATEGORY_PREFIX" = "serverlog" ]; then
        printf 'Deze bron hoort niet bij een enkele installatie, dus dit signaal kon niet tegen een WordPress-versie gewogen worden.'
        return 0
    fi
    if [ -z "$WP2SHELL_LOG_SITE_VERSION" ]; then
        printf 'De WordPress-versie kon niet van schijf gelezen worden, dus dit signaal kon niet tegen de versie gewogen worden.'
        return 0
    fi
    case $WP2SHELL_LOG_SITE_STATUS in
        rce-vulnerable)
            printf 'De versie op schijf is %s en valt in het kwetsbare bereik van CVE-2026-63030, wat dit signaal zwaar laat wegen.' \
                "$WP2SHELL_LOG_SITE_VERSION"
            ;;
        sqli-latent)
            printf 'De versie op schijf is %s. De route-verwarring in de batch-controller bestaat pas vanaf 6.9, dus een geslaagd batch-verzoek is hier waarschijnlijk gewoon verkeer van een ingelogde redacteur.' \
                "$WP2SHELL_LOG_SITE_VERSION"
            ;;
        patched|not-affected)
            printf 'De versie op schijf is %s en staat niet in het kwetsbare bereik, wat dit signaal lichter laat wegen. Let wel op: de versie van vandaag zegt niets over de versie die tijdens deze logregels draaide.' \
                "$WP2SHELL_LOG_SITE_VERSION"
            ;;
        *)
            printf 'De versie op schijf is %s en kon niet ingedeeld worden, dus dit signaal is niet tegen de versie gewogen.' \
                "$WP2SHELL_LOG_SITE_VERSION"
            ;;
    esac
    return 0
}

detect_logs_observation_sentence() {
    local key=$1
    local count first last source statuses
    count=${WP2SHELL_LOG_GROUP_COUNT["$key"]:-0}
    first=${WP2SHELL_LOG_GROUP_FIRST_SEEN["$key"]:-}
    last=${WP2SHELL_LOG_GROUP_LAST_SEEN["$key"]:-}
    source=${WP2SHELL_LOG_GROUP_SOURCE["$key"]:-}
    statuses=${WP2SHELL_LOG_GROUP_STATUSES["$key"]:-}
    printf 'Aantal samengevatte logregels: %s.' "$count"
    if [ -n "$first" ] && [ -n "$last" ]; then
        printf ' Eerste waarneming: %s. Laatste waarneming: %s.' "$first" "$last"
    else
        printf ' Er konden geen tijdstempels uit de logregels gelezen worden.'
    fi
    if [ -n "$statuses" ]; then
        printf ' Waargenomen statuscodes:%s.' "$statuses"
    fi
    if [ -n "$source" ]; then
        printf ' Eerste bronbestand: %s.' "$source"
    fi
    if [ "${WP2SHELL_LOG_FILES_SCANNED:-0}" -gt 1 ]; then
        printf ' Er zijn %s logbestanden doorzocht.' "$WP2SHELL_LOG_FILES_SCANNED"
    fi
    return 0
}

detect_logs_scope_sentence() {
    if [ "$WP2SHELL_LOG_CATEGORY_PREFIX" = "serverlog" ]; then
        printf 'Deze regels komen uit de serverbrede webserverlogs en zijn niet naar een enkele vhost te herleiden.'
        return 0
    fi
    printf 'Deze regels komen uit de logs van dit domein.'
    return 0
}

detect_logs_emit_batch_finding() {
    local site_path=$1 key=$2
    local subtype=${key#*|}
    local severity confidence category title detail remediation
    local observation scope version_note
    observation=$(detect_logs_observation_sentence "$key")
    scope=$(detect_logs_scope_sentence)
    version_note=$(detect_logs_version_sentence)
    local shared_note
    shared_note='De REST batch-API bestaat sinds WordPress 5.6 en wordt ook door ingelogde redacteuren gebruikt, dus de aanwezigheid van de route bewijst op zichzelf niets. Controleer of dit verkeer bij bekend beheerdersverkeer hoort.'
    remediation='Behandel deze installatie als mogelijk gecompromitteerd: controleer bestanden, adminaccounts, mu-plugins en geplande taken, en roteer wachtwoorden, databasegegevens en de salts in wp-config.php.'
    case $subtype in
        207)
            severity=$SEVERITY_CRITICAL
            confidence=$CONFIDENCE_HIGH
            category="$WP2SHELL_LOG_CATEGORY_PREFIX-batch-endpoint-success"
            title='Geslaagd batch-verzoek met status 207 in de logs'
            detail="Er zijn aanroepen van de REST batch-route gevonden die met 207 Multi-Status zijn beantwoord. Die status komt van de batch-controller zelf en betekent dat WordPress de gebundelde deelverzoeken heeft uitgevoerd. Dit is het sterkste netwerksignaal voor misbruik van CVE-2026-63030. $observation $scope $version_note $shared_note"
            ;;
        200)
            category="$WP2SHELL_LOG_CATEGORY_PREFIX-batch-endpoint-success"
            if detect_logs_version_carries_batch_route_flaw; then
                severity=$SEVERITY_CRITICAL
                confidence=$CONFIDENCE_HIGH
                if [ "$WP2SHELL_LOG_SITE_STATUS" = "rce-vulnerable" ]; then
                    title='Geslaagd batch-verzoek met status 200 op een kwetsbare versie'
                else
                    title='Geslaagd batch-verzoek met status 200, versie niet vast te stellen'
                fi
            else
                severity=$SEVERITY_HIGH
                confidence=$CONFIDENCE_HEURISTIC
                title='Geslaagd batch-verzoek met status 200, versie niet in het kwetsbare bereik'
            fi
            detail="Er zijn aanroepen van de REST batch-route gevonden die met status 200 zijn beantwoord, dus het verzoek is verwerkt en niet geweigerd. $observation $scope $version_note $shared_note"
            ;;
        probe)
            severity=$SEVERITY_LOW
            confidence=$CONFIDENCE_HEURISTIC
            category="$WP2SHELL_LOG_CATEGORY_PREFIX-batch-endpoint-probe"
            title='Afgewezen verzoeken op de REST batch-route'
            detail="Er zijn aanroepen van de REST batch-route gevonden die met een 4xx-status zijn afgewezen. Dat wijst op aftasten en niet op een geslaagde aanval. $observation $scope $version_note"
            remediation='Geen directe actie nodig. Zorg dat de installatie op een gepatchte versie staat en houd het patroon in de gaten.'
            ;;
        error)
            severity=$SEVERITY_MEDIUM
            confidence=$CONFIDENCE_HEURISTIC
            category="$WP2SHELL_LOG_CATEGORY_PREFIX-batch-endpoint-anomaly"
            title='Serverfouten op de REST batch-route'
            detail="Er zijn aanroepen van de REST batch-route gevonden die met een 5xx-status eindigden. Een mislukte of half uitgevoerde poging geeft ook fouten, dus dit verdient handmatige beoordeling. $observation $scope $version_note"
            ;;
        unknown|other)
            severity=$SEVERITY_MEDIUM
            confidence=$CONFIDENCE_HEURISTIC
            category="$WP2SHELL_LOG_CATEGORY_PREFIX-batch-endpoint-anomaly"
            title='Verzoeken op de REST batch-route zonder leesbare statuscode'
            detail="Er zijn aanroepen van de REST batch-route gevonden waarvan de statuscode niet uit het logformaat te lezen was, of die een andere status dan 2xx, 4xx of 5xx opleverden. Daardoor kan niet vastgesteld worden of het verzoek geslaagd is. $observation $scope $version_note $shared_note"
            ;;
        weak-medium)
            severity=$SEVERITY_LOW
            confidence=$CONFIDENCE_HEURISTIC
            category="$WP2SHELL_LOG_CATEGORY_PREFIX-batch-endpoint-weak"
            title='Aanroepen van de REST-API via een rest_route-parameter'
            detail="Er zijn verzoeken gevonden die de REST-API via een rest_route-parameter aanspreken, zonder dat de batch-route zelf herkend werd. Dit is op zichzelf normaal verkeer en alleen relevant als er andere signalen bij staan. $observation $scope"
            remediation='Alleen handmatig beoordelen als er andere bevindingen voor deze site zijn.'
            ;;
        weak-low)
            severity=$SEVERITY_INFO
            confidence=$CONFIDENCE_HEURISTIC
            category="$WP2SHELL_LOG_CATEGORY_PREFIX-batch-endpoint-weak"
            title='Verzoeken met opeenvolgende schuine strepen in het pad'
            detail="Er zijn verzoeken gevonden met opeenvolgende schuine strepen in het pad. Die vorm wordt gebruikt om routecontroles te omzeilen, maar komt ook door slordige links en scanners voort. $observation $scope"
            remediation='Alleen handmatig beoordelen als er andere bevindingen voor deze site zijn.'
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
        "file=${WP2SHELL_LOG_GROUP_SOURCE["$key"]:-}" \
        "evidence=${WP2SHELL_LOG_GROUP_EVIDENCE["$key"]:-}" \
        "remediation=$remediation"
    return 0
}

detect_logs_emit_sqli_finding() {
    local site_path=$1 key=$2
    local parameter observation scope sample detail
    parameter=${WP2SHELL_LOG_GROUP_LABEL["$key"]:-onbekend}
    observation=$(detect_logs_observation_sentence "$key")
    scope=$(detect_logs_scope_sentence)
    sample=${WP2SHELL_LOG_GROUP_SAMPLE["$key"]:-}
    detail="Er zijn verzoeken gevonden waarin de parameter $parameter een waarde meekrijgt die geen geheel getal of lijst gehele getallen is. Deze parameter hoort uitsluitend gebruikers-ID's te bevatten, dus een andere waarde wijst op een poging tot misbruik van de SQL-injectie CVE-2026-60137. Verzoeken waarin de parameter wel een geldige numerieke waarde had, zijn niet meegeteld. $observation $scope"
    if [ -n "$sample" ]; then
        detail="$detail Voorbeeldwaarde uit de logregel: $sample"
    fi
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_HIGH" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=$WP2SHELL_LOG_CATEGORY_PREFIX-sqli-attempt" \
        "title=SQL-injectiepoging via de parameter $parameter" \
        "detail=$detail" \
        "file=${WP2SHELL_LOG_GROUP_SOURCE["$key"]:-}" \
        "evidence=${WP2SHELL_LOG_GROUP_EVIDENCE["$key"]:-}" \
        "remediation=Controleer of de installatie gepatcht is, beoordeel de betrokken bestanden en accounts, en ga er bij een geslaagde injectie van uit dat wachtwoordhashes van beheerders uitgelezen zijn."
    return 0
}

detect_logs_emit_lfi_finding() {
    local site_path=$1 key=$2
    local subtype=${key#*|}
    local observation scope severity title detail
    observation=$(detect_logs_observation_sentence "$key")
    scope=$(detect_logs_scope_sentence)
    if [ "$subtype" = "success" ]; then
        severity=$SEVERITY_CRITICAL
        title='Geslaagd uitlezen van wp-config.php via admin-ajax.php'
        detail="Er zijn verzoeken naar admin-ajax.php gevonden met een template-parameter die via padtraversal naar wp-config.php wijst, en die met status 200 zijn beantwoord. Ga ervan uit dat de inhoud van wp-config.php is buitgemaakt: de databasegebruiker, het databasewachtwoord, de tabelprefix en alle authenticatiesalts. $observation $scope"
    else
        severity=$SEVERITY_HIGH
        title='Poging tot uitlezen van wp-config.php via admin-ajax.php'
        detail="Er zijn verzoeken naar admin-ajax.php gevonden met een template-parameter die via padtraversal naar wp-config.php wijst. De statuscode wijst niet op een geslaagd verzoek, maar het logformaat kan de status ook missen. Bij een geslaagd verzoek zijn de databasegegevens en de authenticatiesalts uit wp-config.php gelezen. $observation $scope"
    fi
    record_finding \
        "site=$site_path" \
        "severity=$severity" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=$WP2SHELL_LOG_CATEGORY_PREFIX-lfi-wp-config" \
        "title=$title" \
        "detail=$detail" \
        "file=${WP2SHELL_LOG_GROUP_SOURCE["$key"]:-}" \
        "evidence=${WP2SHELL_LOG_GROUP_EVIDENCE["$key"]:-}" \
        "remediation=Roteer het databasewachtwoord, vervang alle salts in wp-config.php zodat lopende sessies ongeldig worden, en reset de wachtwoorden van alle beheerders. Alleen een webshell verwijderen is hier niet voldoende, want de gelekte gegevens blijven anders bruikbaar."
    return 0
}

detect_logs_emit_useragent_finding() {
    local site_path=$1 key=$2
    local literal observation scope
    literal=${WP2SHELL_LOG_GROUP_LABEL["$key"]:-onbekend}
    observation=$(detect_logs_observation_sentence "$key")
    scope=$(detect_logs_scope_sentence)
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_LOW" \
        "confidence=$CONFIDENCE_HEURISTIC" \
        "category=$WP2SHELL_LOG_CATEGORY_PREFIX-user-agent" \
        "title=Bekende proof-of-concept user agent in de logs: $literal" \
        "detail=Er zijn logregels gevonden met de tekst $literal, die als standaard user agent in publieke proof-of-concept code voorkomt. Dat is triviaal aan te passen, dus gebruik dit alleen als triage en nooit als bewijs. Het ontbreken van deze user agent zegt niets over de afwezigheid van misbruik. $observation $scope" \
        "file=${WP2SHELL_LOG_GROUP_SOURCE["$key"]:-}" \
        "evidence=${WP2SHELL_LOG_GROUP_EVIDENCE["$key"]:-}" \
        "remediation=Beoordeel deze regels samen met de overige bevindingen voor deze site."
    return 0
}

detect_logs_category_title() {
    case $1 in
        plugin-upload) printf 'Uploaden van een plugin via de beheeromgeving in de logs' ;;
        user-enumeration) printf 'Opsomming van gebruikers via de REST-API in de logs' ;;
        command-channel) printf 'Markering van een wp2shell commandokanaal in de logs' ;;
        *) printf 'Logpatroon uit de IOC-lijst aangetroffen: %s' "$1" ;;
    esac
    return 0
}

detect_logs_category_detail() {
    case $1 in
        plugin-upload)
            printf 'Er zijn verzoeken gevonden naar de pluginupload van WordPress. Beheerders doen dit ook zelf, dus dit is pas relevant in combinatie met andere signalen of wanneer het tijdstip niet bij bekend beheerderswerk past.'
            ;;
        user-enumeration)
            printf 'Er zijn verzoeken gevonden die via de REST-API de gebruikerslijst opvragen. Dat gebeurt ook door legitieme plugins en door het blok-editor-verkeer van ingelogde redacteuren.'
            ;;
        command-channel)
            printf 'Er zijn logregels gevonden met een markering die in de uitvoer van een wp2shell-commandokanaal voorkomt. In een webserverlog kan die tekst ook uit een verzoekparameter of een user agent komen, dus dit is een aanwijzing en geen bewijs.'
            ;;
        *)
            printf 'Er zijn logregels gevonden die overeenkomen met een patroon uit de IOC-lijst voor categorie %s.' "$1"
            ;;
    esac
    return 0
}

detect_logs_emit_pattern_finding() {
    local site_path=$1 key=$2
    local remainder category tier severity confidence title detail observation scope
    remainder=${key#*|}
    category=${remainder%%|*}
    tier=${remainder##*|}
    severity=$(detect_logs_tier_severity "$tier")
    confidence=$(detect_logs_tier_confidence "$tier")
    title=$(detect_logs_category_title "$category")
    detail=$(detect_logs_category_detail "$category")
    observation=$(detect_logs_observation_sentence "$key")
    scope=$(detect_logs_scope_sentence)
    record_finding \
        "site=$site_path" \
        "severity=$severity" \
        "confidence=$confidence" \
        "category=$WP2SHELL_LOG_CATEGORY_PREFIX-$category" \
        "title=$title" \
        "detail=$detail $observation $scope" \
        "file=${WP2SHELL_LOG_GROUP_SOURCE["$key"]:-}" \
        "evidence=${WP2SHELL_LOG_GROUP_EVIDENCE["$key"]:-}" \
        "remediation=Beoordeel deze regels samen met de overige bevindingen voor deze site."
    return 0
}

detect_logs_emit_ip_finding() {
    local site_path=$1 key=$2
    local index address position tier description severity title detail observation scope
    index=${WP2SHELL_LOG_GROUP_LABEL["$key"]:-}
    case $index in
        ''|*[!0-9]*) return 0 ;;
    esac
    address=${WP2SHELL_LOG_IP_ADDRESS[index]}
    tier=${WP2SHELL_LOG_IP_TIER[index]}
    description=${WP2SHELL_LOG_IP_DESCRIPTION[index]}
    position=${key##*|}
    severity=$(detect_logs_tier_severity "$tier")
    observation=$(detect_logs_observation_sentence "$key")
    scope=$(detect_logs_scope_sentence)
    if [ "$position" = "elders" ]; then
        severity=$SEVERITY_INFO
        title="IOC-adres $address komt voor in een logregel, niet als client"
        detail="Het adres $address staat in de IOC-lijst en komt in logregels voor, maar niet in het clientveld. Dat kan een verwijzende URL of een user agent zijn en is daarmee een zeer zwak signaal."
    else
        title="Verkeer van IOC-adres $address"
        detail="Het adres $address staat als client in de logs en komt voor in de IOC-lijst."
    fi
    if [ "$tier" = "low" ]; then
        detail="$detail Toelichting uit de IOC-lijst: $description. Dit adres hoort bij gedeelde cloud- of scaninfrastructuur. Op een gedeelde server komt zo'n massascanner in de logs van iedere vhost voor. Dit is uitdrukkelijk geen bewijs van compromittering en mag ook niet zo gepresenteerd worden."
    else
        detail="$detail Toelichting uit de IOC-lijst: $description. Dit adres ligt niet in een bekende cloudrange, waardoor het iets zwaarder weegt. Het blijft een signaal en geen bewijs."
    fi
    record_finding \
        "site=$site_path" \
        "severity=$severity" \
        "confidence=$CONFIDENCE_HEURISTIC" \
        "category=$WP2SHELL_LOG_CATEGORY_PREFIX-attacker-ip" \
        "title=$title" \
        "detail=$detail $observation $scope" \
        "file=${WP2SHELL_LOG_GROUP_SOURCE["$key"]:-}" \
        "evidence=${WP2SHELL_LOG_GROUP_EVIDENCE["$key"]:-}" \
        "remediation=Gebruik dit adres alleen als zoeksleutel bij de overige bevindingen. Blokkeer niet automatisch op basis van deze lijst."
    return 0
}

detect_logs_emit_groups() {
    local site_path=$1
    local key kind
    if [ "${#WP2SHELL_LOG_GROUP_KEYS[@]}" -eq 0 ]; then
        return 0
    fi
    for key in "${WP2SHELL_LOG_GROUP_KEYS[@]}"; do
        kind=${key%%|*}
        case $kind in
            batch) detect_logs_emit_batch_finding "$site_path" "$key" ;;
            sqli) detect_logs_emit_sqli_finding "$site_path" "$key" ;;
            lfi) detect_logs_emit_lfi_finding "$site_path" "$key" ;;
            useragent) detect_logs_emit_useragent_finding "$site_path" "$key" ;;
            pattern) detect_logs_emit_pattern_finding "$site_path" "$key" ;;
            ip) detect_logs_emit_ip_finding "$site_path" "$key" ;;
        esac
    done
    return 0
}

detect_logs_join_entries() {
    local limit=$1
    shift
    local entry joined='' shown=0
    for entry in "$@"; do
        if [ "$shown" -ge "$limit" ]; then
            joined="$joined, en meer"
            break
        fi
        if [ -z "$joined" ]; then
            joined="$entry"
        else
            joined="$joined, $entry"
        fi
        shown=$((shown + 1))
    done
    printf '%s' "$joined"
    return 0
}

detect_logs_emit_source_findings() {
    local site_path=$1 subject=$2
    local probed read_list
    probed=''
    if [ "${#WP2SHELL_LOG_DIRECTORIES_PROBED[@]}" -gt 0 ]; then
        probed=$(detect_logs_join_entries 12 "${WP2SHELL_LOG_DIRECTORIES_PROBED[@]}")
    fi
    read_list=''
    if [ "${#WP2SHELL_LOG_SOURCES_READ[@]}" -gt 0 ]; then
        read_list=$(detect_logs_join_entries 12 "${WP2SHELL_LOG_SOURCES_READ[@]}")
    fi
    if [ "${#WP2SHELL_LOG_SOURCES_READ[@]}" -eq 0 ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_INFO" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=$WP2SHELL_LOG_CATEGORY_PREFIX-missing" \
            "title=Geen webserverlogs gevonden voor $subject" \
            "detail=Er is geen enkel logbestand gevonden of gelezen voor $subject. Zonder logs kan uit deze bron niet vastgesteld worden of er misbruik heeft plaatsgevonden. Het ontbreken van loghistorie is dus geen aanwijzing dat er niets gebeurd is. Geprobeerde locaties: $probed" \
            "remediation=Controleer waar de webserver voor deze bron logt, controleer of de scan als root draait, en verleng zo nodig de bewaartermijn van de logrotatie."
    else
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_INFO" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=$WP2SHELL_LOG_CATEGORY_PREFIX-sources" \
            "title=Gelezen logbronnen voor $subject" \
            "detail=Er zijn ${#WP2SHELL_LOG_SOURCES_READ[@]} logbestanden gelezen. Geprobeerde locaties: $probed" \
            "evidence=$read_list"
    fi
    if [ "${#WP2SHELL_LOG_SOURCES_FAILED[@]}" -gt 0 ] || [ "$WP2SHELL_LOG_COLLECTION_INCOMPLETE" = "1" ]; then
        local failed
        failed=''
        if [ "${#WP2SHELL_LOG_SOURCES_FAILED[@]}" -gt 0 ]; then
            failed=$(detect_logs_join_entries 12 "${WP2SHELL_LOG_SOURCES_FAILED[@]}")
        fi
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=$WP2SHELL_LOG_CATEGORY_PREFIX-scan-incomplete" \
            "title=De loganalyse voor $subject is onvolledig" \
            "detail=Niet alle logbronnen konden gelezen worden. Deze uitkomst mag niet gelezen worden als bewijs dat er niets in de logs staat. Details: $failed Geprobeerde locaties: $probed" \
            "remediation=Draai de scan als root en controleer de rechten op de logmappen."
    fi
    if [ "${#WP2SHELL_LOG_SOURCES_TRUNCATED[@]}" -gt 0 ]; then
        local truncated
        truncated=$(detect_logs_join_entries 12 "${WP2SHELL_LOG_SOURCES_TRUNCATED[@]}")
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=$WP2SHELL_LOG_CATEGORY_PREFIX-scan-truncated" \
            "title=De loganalyse voor $subject is afgekapt" \
            "detail=Een of meer logbestanden zijn niet volledig verwerkt omdat de ingestelde limieten bereikt zijn of omdat de stroom voortijdig eindigde. Er kunnen dus regels gemist zijn. Details: $truncated" \
            "remediation=Verhoog WP2SHELL_LOG_SCAN_MAX_LINES of WP2SHELL_LOG_SCAN_MAX_MATCHES in de configuratie en draai de loganalyse opnieuw voor deze bron."
    fi
    return 0
}

detect_logs_prepare_work_dir() {
    WP2SHELL_LOG_WORK_DIR=$(make_temp_dir wp2shell-logs) || return 1
    register_temp_cleanup "$WP2SHELL_LOG_WORK_DIR"
    return 0
}

detect_logs_release_work_dir() {
    if [ -n "$WP2SHELL_LOG_WORK_DIR" ] && [ -d "$WP2SHELL_LOG_WORK_DIR" ]; then
        rm -rf -- "$WP2SHELL_LOG_WORK_DIR"
    fi
    WP2SHELL_LOG_WORK_DIR=""
    return 0
}

detect_logs_for_site() {
    local site_path=${1:-}
    local domain=${2:-}
    if [ -z "$site_path" ]; then
        log_error "detect_logs_for_site vereist een sitepad"
        return "$EXIT_INTERNAL"
    fi
    if [ "${WP2SHELL_SCAN_LOGS:-1}" != "1" ]; then
        log_debug "Loganalyse staat uit, $site_path wordt overgeslagen"
        return 0
    fi
    if ! detect_logs_load_iocs; then
        return "$EXIT_INTERNAL"
    fi
    if [ -z "$domain" ] && [ "${WP2SHELL_DISCOVERY_LOADED:-0}" = "1" ]; then
        domain=$(domain_from_path "$site_path") || domain=''
    fi
    detect_logs_reset_state
    WP2SHELL_LOG_CATEGORY_PREFIX="log"
    if ! detect_logs_prepare_work_dir; then
        log_error "Kan geen werkmap maken voor de loganalyse van $site_path"
        return "$EXIT_INTERNAL"
    fi
    detect_logs_resolve_site_version "$site_path"
    local subject="$site_path"
    if [ -n "$domain" ]; then
        subject="$domain"
    fi
    local pattern_file="$WP2SHELL_LOG_WORK_DIR/patterns"
    local address_pattern_file="$WP2SHELL_LOG_WORK_DIR/patterns-addresses"
    local candidates="$WP2SHELL_LOG_WORK_DIR/candidates"
    if ! detect_logs_write_grep_patterns "$pattern_file" signatures; then
        log_error "Geen zoekpatronen beschikbaar voor de loganalyse"
        detect_logs_release_work_dir
        return "$EXIT_INTERNAL"
    fi
    detect_logs_write_grep_patterns "$address_pattern_file" addresses || : > "$address_pattern_file"
    if [ -z "$domain" ]; then
        log_warn "Geen domein bekend voor $site_path, per-domein logs kunnen niet geprobeerd worden"
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_INFO" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=log-missing" \
            "title=Geen domein bekend, logs niet te herleiden" \
            "detail=Voor deze installatie is geen domeinnaam bepaald, dus de per-domein logbestanden konden niet geprobeerd worden. De loganalyse zegt daarom niets over deze installatie." \
            "remediation=Controleer de docroot en de domeinregistratie in DirectAdmin en draai de scan opnieuw met een expliciet domein."
        detect_logs_release_work_dir
        return 0
    fi
    log_debug "Loganalyse gestart voor $subject"
    detect_logs_collect_domain_files "$domain" "$candidates"
    detect_logs_scan_candidates "$candidates" "$pattern_file"
    if [ -s "$address_pattern_file" ]; then
        detect_logs_scan_candidates "$candidates" "$address_pattern_file"
    fi
    detect_logs_emit_groups "$site_path"
    detect_logs_emit_source_findings "$site_path" "$subject"
    log_info "Loganalyse voor $subject klaar, $WP2SHELL_LOG_FILES_SCANNED logbestanden verwerkt"
    detect_logs_release_work_dir
    return 0
}

detect_logs_server_wide() {
    if [ "${WP2SHELL_SCAN_LOGS:-1}" != "1" ]; then
        log_debug "Loganalyse staat uit, de serverbrede sweep wordt overgeslagen"
        return 0
    fi
    if ! detect_logs_load_iocs; then
        return "$EXIT_INTERNAL"
    fi
    detect_logs_reset_state
    WP2SHELL_LOG_CATEGORY_PREFIX="serverlog"
    WP2SHELL_LOG_SITE_VERSION=""
    WP2SHELL_LOG_SITE_STATUS="unknown"
    if ! detect_logs_prepare_work_dir; then
        log_error "Kan geen werkmap maken voor de serverbrede loganalyse"
        return "$EXIT_INTERNAL"
    fi
    local pattern_file="$WP2SHELL_LOG_WORK_DIR/patterns"
    local address_pattern_file="$WP2SHELL_LOG_WORK_DIR/patterns-addresses"
    local candidates="$WP2SHELL_LOG_WORK_DIR/candidates"
    if ! detect_logs_write_grep_patterns "$pattern_file" signatures; then
        log_error "Geen zoekpatronen beschikbaar voor de serverbrede loganalyse"
        detect_logs_release_work_dir
        return "$EXIT_INTERNAL"
    fi
    detect_logs_write_grep_patterns "$address_pattern_file" addresses || : > "$address_pattern_file"
    log_debug "Serverbrede loganalyse gestart"
    detect_logs_collect_server_files "$candidates"
    detect_logs_scan_candidates "$candidates" "$pattern_file"
    if [ -s "$address_pattern_file" ]; then
        detect_logs_scan_candidates "$candidates" "$address_pattern_file"
    fi
    detect_logs_emit_groups ""
    detect_logs_emit_source_findings "" "de serverbrede logs"
    log_info "Serverbrede loganalyse klaar, $WP2SHELL_LOG_FILES_SCANNED logbestanden verwerkt"
    detect_logs_release_work_dir
    return 0
}
