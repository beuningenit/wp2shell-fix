WP2SHELL_DETECT_HOST_LOADED=1

WP2SHELL_DETECT_HOST_COMPLETED=0
WP2SHELL_DETECT_HOST_USER_SOURCE=""

WP2SHELL_DETECT_HOST_CRON_PATTERNS_READY=0
WP2SHELL_DETECT_HOST_CRON_STRONG_LABELS=()
WP2SHELL_DETECT_HOST_CRON_STRONG_REGEXES=()
WP2SHELL_DETECT_HOST_CRON_WEAK_LABELS=()
WP2SHELL_DETECT_HOST_CRON_WEAK_REGEXES=()

WP2SHELL_DETECT_HOST_CRON_SOURCES_READ=0
WP2SHELL_DETECT_HOST_CRON_FILES_READ=0
WP2SHELL_DETECT_HOST_CRON_STRONG_FINDINGS=0
WP2SHELL_DETECT_HOST_CRON_STRONG_SUPPRESSED=0
WP2SHELL_DETECT_HOST_CRON_WEAK_COUNT=0
WP2SHELL_DETECT_HOST_CRON_WEAK_SAMPLES=()
WP2SHELL_DETECT_HOST_CRON_UNREADABLE=()

WP2SHELL_DETECT_HOST_KEY_FINDINGS=0
WP2SHELL_DETECT_HOST_KEY_SUPPRESSED=0
WP2SHELL_DETECT_HOST_KEY_UNREADABLE=()

WP2SHELL_DETECT_HOST_WRITABLE_COUNT=0
WP2SHELL_DETECT_HOST_WRITABLE_SAMPLES=()
WP2SHELL_DETECT_HOST_WRITABLE_INCOMPLETE=0
WP2SHELL_DETECT_HOST_WRITABLE_BASES=0

WP2SHELL_DETECT_HOST_PROCESS_FINDINGS=0

WP2SHELL_DETECT_HOST_PRUNE_ARGS=()
WP2SHELL_DETECT_HOST_PRUNE_FALLBACK_NAMES=(
    "node_modules"
    ".git"
    ".svn"
    ".wp-cli"
    "wp2shell-quarantine"
    "wp2shell-backup"
)

WP2SHELL_DETECT_HOST_USER_CRON_DIRS=(
    "/var/spool/cron"
    "/var/spool/cron/crontabs"
)

WP2SHELL_DETECT_HOST_SYSTEM_CRON_DIRS=(
    "/etc/cron.d"
)

WP2SHELL_DETECT_HOST_SCRIPT_CRON_DIRS=(
    "/etc/cron.hourly"
    "/etc/cron.daily"
    "/etc/cron.weekly"
    "/etc/cron.monthly"
)

WP2SHELL_DETECT_HOST_SYSTEM_CRON_FILES=(
    "/etc/crontab"
)

detect_host_snippet() {
    local raw=$1
    local limit=${WP2SHELL_HOST_EVIDENCE_CHARS:-160}
    raw=${raw//$'\t'/ }
    raw=${raw//$'\n'/ }
    raw=${raw//$'\r'/ }
    while [ "${raw:0:1}" = " " ]; do
        raw=${raw:1}
    done
    if [ "${#raw}" -gt "$limit" ]; then
        raw="${raw:0:$limit}..."
    fi
    printf '%s' "$raw"
    return 0
}

detect_host_trim_leading_space() {
    local raw=$1
    while [ "${raw:0:1}" = " " ] || [ "${raw:0:1}" = $'\t' ]; do
        raw=${raw:1}
    done
    printf '%s' "$raw"
    return 0
}

detect_host_join_samples() {
    local first=1 entry
    for entry in "$@"; do
        if [ "$first" = "1" ]; then
            first=0
        else
            printf ' || '
        fi
        printf '%s' "$entry"
    done
    return 0
}

detect_host_record_gap() {
    local category=$1 title=$2 detail=$3 remediation=$4
    local file_path=${5:-}
    record_finding \
        "severity=$SEVERITY_MEDIUM" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=$category" \
        "title=$title" \
        "detail=$detail" \
        "file=$file_path" \
        "remediation=$remediation"
    return 0
}

detect_host_directory_is_listable() {
    local dir=$1
    if [ ! -d "$dir" ]; then
        return 1
    fi
    "${WP2SHELL_FIND:-find}" -P "$dir" -mindepth 1 -maxdepth 1 \
        -name 'wp2shell-listability-probe' >/dev/null 2>&1
}

detect_host_collect_files_into() {
    local dir=$1 destination=$2 status=0
    : > "$destination"
    "${WP2SHELL_FIND:-find}" -P "$dir" -mindepth 1 -maxdepth 1 -type f -print0 \
        > "$destination" 2>/dev/null || status=$?
    return "$status"
}

detect_host_build_prune_arguments() {
    WP2SHELL_DETECT_HOST_PRUNE_ARGS=()
    local -a names=()
    if [ -n "${WP2SHELL_PRUNE_DIR_NAMES[*]+x}" ]; then
        names=("${WP2SHELL_PRUNE_DIR_NAMES[@]}")
    fi
    if [ "${#names[@]}" -eq 0 ]; then
        names=("${WP2SHELL_DETECT_HOST_PRUNE_FALLBACK_NAMES[@]}")
    fi
    local name first=1
    WP2SHELL_DETECT_HOST_PRUNE_ARGS+=('(')
    for name in "${names[@]}"; do
        if [ "$first" = "1" ]; then
            first=0
        else
            WP2SHELL_DETECT_HOST_PRUNE_ARGS+=(-o)
        fi
        WP2SHELL_DETECT_HOST_PRUNE_ARGS+=(-name "$name")
    done
    WP2SHELL_DETECT_HOST_PRUNE_ARGS+=(')' -prune -o)
    return 0
}

detect_host_load_prefix() {
    if [ -z "${WP2SHELL_LOAD_PREFIX[*]+x}" ]; then
        build_load_prefix
    fi
    return 0
}

detect_host_running_as_root() {
    local uid
    uid=$(id -u 2>/dev/null) || uid=''
    [ "$uid" = "0" ]
}

detect_host_report_privilege_gap() {
    if detect_host_running_as_root; then
        return 0
    fi
    detect_host_record_gap \
        "host-checks-unprivileged" \
        "De hostcontroles draaien zonder rootrechten" \
        "De crontabs onder /var/spool/cron, de SSH-sleutels van de klanten en /etc/ld.so.preload zijn alleen als root volledig leesbaar. Deze run draait als $(current_user_name), dus een deel van de hostcontroles kan niets gezien hebben. Het uitblijven van bevindingen in dit onderdeel zegt daarom niets over de staat van de server." \
        "Draai de hostcontroles als root en beoordeel de uitkomst daarvan."
    return 0
}

detect_host_user_home() {
    local user=$1
    if declare -F directadmin_user_home >/dev/null 2>&1; then
        directadmin_user_home "$user"
        return 0
    fi
    user_home_dir "$user"
    return 0
}

detect_host_collect_users_into() {
    local destination=$1
    local users_dir=${WP2SHELL_DIRECTADMIN_USERS_DIR:-/usr/local/directadmin/data/users}
    local home_base=${WP2SHELL_HOME_BASE:-/home}
    local entry name
    WP2SHELL_DETECT_HOST_USER_SOURCE=""
    : > "$destination"
    if detect_host_directory_is_listable "$users_dir"; then
        for entry in "$users_dir"/*; do
            if [ ! -d "$entry" ]; then
                continue
            fi
            name=${entry##*/}
            if [ -z "$name" ] || [ "$name" = '*' ]; then
                continue
            fi
            printf '%s\n' "$name" >> "$destination"
        done
        WP2SHELL_DETECT_HOST_USER_SOURCE="directadmin"
        return 0
    fi
    for entry in "$home_base"/*; do
        if [ ! -d "$entry/domains" ]; then
            continue
        fi
        name=${entry##*/}
        if [ -z "$name" ] || [ "$name" = '*' ]; then
            continue
        fi
        printf '%s\n' "$name" >> "$destination"
    done
    if [ -s "$destination" ]; then
        WP2SHELL_DETECT_HOST_USER_SOURCE="homedirs"
        return 0
    fi
    return 1
}

detect_host_report_user_enumeration_source() {
    case $WP2SHELL_DETECT_HOST_USER_SOURCE in
        directadmin) return 0 ;;
        homedirs)
            detect_host_record_gap \
                "host-user-enumeration-fallback" \
                "De gebruikerslijst komt niet uit de DirectAdmin-administratie" \
                "De map ${WP2SHELL_DIRECTADMIN_USERS_DIR:-/usr/local/directadmin/data/users} kon niet gelezen worden, daarom zijn de gebruikers afgeleid uit de mappen onder ${WP2SHELL_HOME_BASE:-/home}. Gebruikers zonder domains-map vallen daarmee buiten de controle op SSH-sleutels en op wereldschrijfbare mappen." \
                "Controleer of DirectAdmin aanwezig is en of WP2SHELL_DIRECTADMIN_USERS_DIR naar de juiste map wijst, en draai de scan als root."
            return 0
            ;;
    esac
    detect_host_record_gap \
        "host-user-enumeration-failed" \
        "Er kon geen lijst van hostinggebruikers opgebouwd worden" \
        "Noch de DirectAdmin-administratie in ${WP2SHELL_DIRECTADMIN_USERS_DIR:-/usr/local/directadmin/data/users}, noch de mappen onder ${WP2SHELL_HOME_BASE:-/home} leverden gebruikers op. De controle op SSH-sleutels en op wereldschrijfbare mappen in de klantomgevingen is daardoor niet uitgevoerd." \
        "Controleer de paden in de configuratie en draai de hostcontroles opnieuw als root."
    return 0
}

detect_host_add_cron_pattern() {
    local tier=$1 label=$2 pattern=$3
    if [ "$tier" = "strong" ]; then
        WP2SHELL_DETECT_HOST_CRON_STRONG_LABELS+=("$label")
        WP2SHELL_DETECT_HOST_CRON_STRONG_REGEXES+=("$pattern")
        return 0
    fi
    WP2SHELL_DETECT_HOST_CRON_WEAK_LABELS+=("$label")
    WP2SHELL_DETECT_HOST_CRON_WEAK_REGEXES+=("$pattern")
    return 0
}

detect_host_init_cron_patterns() {
    if [ "$WP2SHELL_DETECT_HOST_CRON_PATTERNS_READY" = "1" ]; then
        return 0
    fi
    WP2SHELL_DETECT_HOST_CRON_STRONG_LABELS=()
    WP2SHELL_DETECT_HOST_CRON_STRONG_REGEXES=()
    WP2SHELL_DETECT_HOST_CRON_WEAK_LABELS=()
    WP2SHELL_DETECT_HOST_CRON_WEAK_REGEXES=()
    local interpreter='((ba|z|k|da|a)?sh|php[0-9.]*|perl|python[0-9.]*|ruby|node)'
    local inline='(php[0-9.]*[[:space:]]+-r|python[0-9.]*[[:space:]]+-c|perl[[:space:]]+-e|ruby[[:space:]]+-e|node[[:space:]]+-e)'
    local downloader='(curl|wget|fetch|lwp-download)'
    local flags='(-[a-z0-9]+[[:space:]]+)*'
    local decoder='base64[[:space:]]+(-[^[:space:]]*d|--decode)'
    local boundary='(^|[[:space:]]|;|&|\||\()'
    local command_start="${boundary}(/[^[:space:]]*/)?"
    local stdin_shell='(sh|bash|zsh|ksh|dash)'
    detect_host_add_cron_pattern strong \
        "een downloader die rechtstreeks in een shell wordt gepijpt" \
        "${command_start}${downloader}[^|]*\|[[:space:]]*(/[^[:space:]]*/)?${stdin_shell}([[:space:]]+-[a-z]+)*[[:space:]]*(;|&|\||\)|\$)"
    detect_host_add_cron_pattern strong \
        "een downloader die in een interpreter wordt gepijpt die van standaardinvoer leest" \
        "${command_start}${downloader}[^|]*\|[[:space:]]*(/[^[:space:]]*/)?(php[0-9.]*|python[0-9.]*|perl|ruby|node)([[:space:]]+-[a-z]+)*[[:space:]]*(-|--)?[[:space:]]*(;|&|\||\)|\$)"
    detect_host_add_cron_pattern strong \
        "een base64-decodering die rechtstreeks in een interpreter wordt gepijpt" \
        "${command_start}${decoder}[^|]*\|[[:space:]]*(/[^[:space:]]*/)?${interpreter}([[:space:]]|;|\$)"
    detect_host_add_cron_pattern strong \
        "een verwijzing naar een .onion-adres" \
        "\.onion([^a-z0-9]|\$)"
    detect_host_add_cron_pattern strong \
        "netcat met een optie die een programma aan de verbinding koppelt" \
        "${command_start}(nc|ncat|netcat)[[:space:]]+([^|]*[[:space:]])?(-[a-z]*[ec]|--(sh-)?exec)([[:space:]]|=|\$)"
    detect_host_add_cron_pattern strong \
        "een bestand in /dev/shm dat opgehaald of uitgevoerd wordt" \
        "${command_start}${interpreter}[[:space:]]+${flags}/dev/shm/|${command_start}${downloader}[^|]*[[:space:]]/dev/shm/|/dev/shm/\."
    detect_host_add_cron_pattern strong \
        "een interpreter die zijn code rechtstreeks van een netwerklocatie haalt" \
        "${command_start}(php[0-9.]*|python[0-9.]*|perl|ruby)[[:space:]]+(https?|ftps?)://"
    detect_host_add_cron_pattern weak \
        "inline interpretercode waarin een netwerkadres voorkomt" \
        "${command_start}${inline}[^|]*(https?|ftps?)://"
    detect_host_add_cron_pattern strong \
        "inline interpretercode met een decodeer- of uitvoerfunctie" \
        "${command_start}${inline}[^|]*(eval|assert|base64_decode|gzinflate|gzuncompress|str_rot13|shell_exec|passthru|proc_open|popen|system)[[:space:]]*\("
    detect_host_add_cron_pattern strong \
        "een interpreter die een bestand uit uploads, cache of upgrade uitvoert" \
        "${command_start}${interpreter}[[:space:]]+${flags}[^[:space:]|]*/wp-content/(uploads|cache|upgrade)/"
    detect_host_add_cron_pattern weak \
        "een verwijzing naar /tmp of /var/tmp" \
        "(^|[^a-z0-9_/])/(var/)?tmp/"
    detect_host_add_cron_pattern weak \
        "een verwijzing naar /dev/shm" \
        "/dev/shm/"
    detect_host_add_cron_pattern weak \
        "een shell of interpreter die een bestand uit /tmp of /var/tmp uitvoert" \
        "${command_start}${interpreter}[[:space:]]+${flags}/(var/)?tmp/"
    detect_host_add_cron_pattern weak \
        "inline interpretercode in plaats van een scriptbestand" \
        "${command_start}${inline}([[:space:]]|\$)"
    detect_host_add_cron_pattern weak \
        "een base64-decodering" \
        "${decoder}"
    detect_host_add_cron_pattern weak \
        "rechten die ruim gezet worden" \
        "chmod[[:space:]]+${flags}([0-7]*7[0-7]*|[ugoa]*\+x)([[:space:]]|\$)"
    detect_host_add_cron_pattern weak \
        "een download vanaf een adres zonder domeinnaam" \
        "(https?|ftp)://([0-9]{1,3}\.){3}[0-9]{1,3}"
    WP2SHELL_DETECT_HOST_CRON_PATTERNS_READY=1
    return 0
}

detect_host_first_strong_cron_label() {
    local subject=$1
    local total=${#WP2SHELL_DETECT_HOST_CRON_STRONG_REGEXES[@]}
    local index=0 pattern
    while [ "$index" -lt "$total" ]; do
        pattern=${WP2SHELL_DETECT_HOST_CRON_STRONG_REGEXES[$index]}
        if [[ $subject =~ $pattern ]]; then
            printf '%s' "${WP2SHELL_DETECT_HOST_CRON_STRONG_LABELS[$index]}"
            return 0
        fi
        index=$((index + 1))
    done
    return 1
}

detect_host_weak_cron_labels() {
    local subject=$1
    local total=${#WP2SHELL_DETECT_HOST_CRON_WEAK_REGEXES[@]}
    local index=0 pattern found=0
    while [ "$index" -lt "$total" ]; do
        pattern=${WP2SHELL_DETECT_HOST_CRON_WEAK_REGEXES[$index]}
        if [[ $subject =~ $pattern ]]; then
            if [ "$found" = "1" ]; then
                printf ', '
            fi
            printf '%s' "${WP2SHELL_DETECT_HOST_CRON_WEAK_LABELS[$index]}"
            found=1
        fi
        index=$((index + 1))
    done
    if [ "$found" = "1" ]; then
        return 0
    fi
    return 1
}

detect_host_report_strong_cron_line() {
    local path=$1 number=$2 label=$3 line=$4 source_label=$5
    local maximum=${WP2SHELL_HOST_MAX_CRON_FINDINGS:-50}
    if [ "$WP2SHELL_DETECT_HOST_CRON_STRONG_FINDINGS" -ge "$maximum" ]; then
        WP2SHELL_DETECT_HOST_CRON_STRONG_SUPPRESSED=$((WP2SHELL_DETECT_HOST_CRON_STRONG_SUPPRESSED + 1))
        return 0
    fi
    WP2SHELL_DETECT_HOST_CRON_STRONG_FINDINGS=$((WP2SHELL_DETECT_HOST_CRON_STRONG_FINDINGS + 1))
    record_finding \
        "severity=$SEVERITY_CRITICAL" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=host-cron-persistence" \
        "title=Kwaadaardige cronregel in $path" \
        "detail=Regel $number van deze $source_label bevat $label. Dat is geen vorm die in normaal serverbeheer voorkomt. Een cronregel staat buiten de website: hij overleeft het bijwerken van WordPress, het opschonen van de bestanden en het in quarantaine zetten van de webshell, en zet de besmetting bij de eerstvolgende uitvoering doodleuk terug. Dit is precies het gat dat de stelregel gepatcht is niet schoon beschrijft." \
        "file=$path" \
        "evidence=regel $number: $(detect_host_snippet "$line")" \
        "remediation=Zoek eerst uit welk bestand deze regel aanroept en bewaar dat als bewijs. Verwijder daarna de regel uit de crontab, controleer of de gebruiker nog meer cronregels heeft, en behandel de hele server als gecompromitteerd tot het tegendeel is aangetoond."
    return 0
}

detect_host_note_weak_cron_line() {
    local path=$1 number=$2 labels=$3 line=$4
    local maximum=${WP2SHELL_HOST_MAX_CRON_SAMPLES:-8}
    WP2SHELL_DETECT_HOST_CRON_WEAK_COUNT=$((WP2SHELL_DETECT_HOST_CRON_WEAK_COUNT + 1))
    if [ "${#WP2SHELL_DETECT_HOST_CRON_WEAK_SAMPLES[@]}" -ge "$maximum" ]; then
        return 0
    fi
    WP2SHELL_DETECT_HOST_CRON_WEAK_SAMPLES+=("$path regel $number ($labels): $(detect_host_snippet "$line")")
    return 0
}

detect_host_scan_cron_file() {
    local path=$1 source_label=$2 weak_enabled=$3
    if [ ! -f "$path" ]; then
        return 0
    fi
    if [ ! -r "$path" ]; then
        WP2SHELL_DETECT_HOST_CRON_UNREADABLE+=("$path")
        return 0
    fi
    local size
    size=$(file_size_bytes "$path") || size=''
    case $size in
        ''|*[!0-9]*) size=0 ;;
    esac
    if [ "$size" -eq 0 ]; then
        return 0
    fi
    local maximum_bytes=${WP2SHELL_HOST_MAX_CRON_BYTES:-262144}
    if [ "$size" -gt "$maximum_bytes" ]; then
        detect_host_record_gap \
            "host-cron-unscanned" \
            "Cronbestand $path is niet gecontroleerd" \
            "Dit bestand is $size bytes groot en daarmee groter dan de limiet van $maximum_bytes bytes. Een crontab van deze omvang is op zichzelf al ongewoon. De inhoud is niet beoordeeld, dus deze bron mag niet als gecontroleerd gelden." \
            "Bekijk dit bestand handmatig of verhoog WP2SHELL_HOST_MAX_CRON_BYTES en draai de scan opnieuw." \
            "$path"
        return 0
    fi
    if ! "${WP2SHELL_GREP:-grep}" -I -q -m1 -e . -- "$path" 2>/dev/null; then
        log_debug "Cronbestand is binair of bevat geen leesbare regels: $path"
        return 0
    fi
    WP2SHELL_DETECT_HOST_CRON_FILES_READ=$((WP2SHELL_DETECT_HOST_CRON_FILES_READ + 1))
    local maximum_lines=${WP2SHELL_HOST_MAX_CRON_LINES:-2000}
    local reported_path=$path
    local line trimmed lowered number=0 label labels
    while IFS= read -r line || [ -n "$line" ]; do
        number=$((number + 1))
        if [ "$number" -gt "$maximum_lines" ]; then
            detect_host_record_gap \
                "host-cron-unscanned" \
                "Cronbestand $reported_path is maar gedeeltelijk gecontroleerd" \
                "Dit bestand heeft meer dan $maximum_lines regels. Alleen de eerste $maximum_lines regels zijn beoordeeld, de rest niet. Een aanvaller die zijn regel onderaan een lange crontab zet zou hier buiten beeld blijven." \
                "Bekijk dit bestand handmatig of verhoog WP2SHELL_HOST_MAX_CRON_LINES en draai de scan opnieuw." \
                "$reported_path"
            break
        fi
        line=${line%$'\r'}
        trimmed=$(detect_host_trim_leading_space "$line")
        case $trimmed in
            ''|'#'*) continue ;;
        esac
        lowered=${trimmed,,}
        if label=$(detect_host_first_strong_cron_label "$lowered"); then
            detect_host_report_strong_cron_line "$reported_path" "$number" "$label" "$trimmed" "$source_label"
            continue
        fi
        if [ "$weak_enabled" != "1" ]; then
            continue
        fi
        if labels=$(detect_host_weak_cron_labels "$lowered"); then
            detect_host_note_weak_cron_line "$reported_path" "$number" "$labels" "$trimmed"
        fi
    done < "$path"
    return 0
}

detect_host_scan_cron_directory() {
    local dir=$1 source_label=$2 weak_enabled=$3
    if [ ! -d "$dir" ]; then
        return 0
    fi
    if ! detect_host_directory_is_listable "$dir"; then
        detect_host_record_gap \
            "host-cron-unreadable" \
            "De cronmap $dir kon niet gelezen worden" \
            "Deze map bestaat maar de inhoud is niet op te vragen. Of er cronregels in staan is dus onbekend. Dit is nadrukkelijk iets anders dan een gebruiker zonder crontab, wat het normale geval is, en het mag niet als schoon gelezen worden." \
            "Draai de hostcontroles als root en controleer de rechten op deze map." \
            "$dir"
        return 1
    fi
    WP2SHELL_DETECT_HOST_CRON_SOURCES_READ=$((WP2SHELL_DETECT_HOST_CRON_SOURCES_READ + 1))
    local listing status=0 entry
    listing=$(mktemp -t wp2shell-host-cron.XXXXXXXX) || return 1
    register_temp_cleanup "$listing"
    detect_host_collect_files_into "$dir" "$listing" || status=$?
    if [ "$status" -ne 0 ]; then
        detect_host_record_gap \
            "host-cron-unreadable" \
            "De cronmap $dir is maar gedeeltelijk uitgelezen" \
            "Het doorlopen van deze map gaf exitcode $status, dus er kunnen cronbestanden gemist zijn." \
            "Draai de hostcontroles als root en controleer de rechten op deze map." \
            "$dir"
    fi
    while IFS= read -r -d '' entry; do
        detect_host_scan_cron_file "$entry" "$source_label" "$weak_enabled"
    done < "$listing"
    rm -f -- "$listing"
    return 0
}

detect_host_report_cron_summary() {
    if [ "${#WP2SHELL_DETECT_HOST_CRON_UNREADABLE[@]}" -gt 0 ]; then
        detect_host_record_gap \
            "host-cron-unreadable" \
            "${#WP2SHELL_DETECT_HOST_CRON_UNREADABLE[@]} cronbestanden konden niet gelezen worden" \
            "Deze bestanden bestaan wel maar zijn niet leesbaar voor deze run. De regels erin zijn niet beoordeeld. Een ontbrekende crontab is normaal, een onleesbare crontab is een gat in de controle." \
            "Draai de hostcontroles als root en beoordeel deze bestanden alsnog." \
            "$(detect_host_join_samples "${WP2SHELL_DETECT_HOST_CRON_UNREADABLE[@]}")"
    fi
    if [ "$WP2SHELL_DETECT_HOST_CRON_WEAK_COUNT" -gt 0 ]; then
        record_finding \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HEURISTIC" \
            "category=host-cron-review" \
            "title=$WP2SHELL_DETECT_HOST_CRON_WEAK_COUNT cronregels verdienen een handmatige blik" \
            "detail=Deze regels bevatten een patroon dat ook in gewoon beheer voorkomt, bijvoorbeeld een verwijzing naar /tmp, een inline interpreteropdracht of een base64-decodering. Een lockbestand in /tmp of een php -r in een panelscript is volstrekt normaal, dus elk van deze signalen is op zichzelf te zwak om iets op te baseren. Ze staan hier bewust gebundeld en uitsluitend op heuristisch niveau. Er wordt niets automatisch opgeruimd." \
            "evidence=$(detect_host_join_samples "${WP2SHELL_DETECT_HOST_CRON_WEAK_SAMPLES[@]+"${WP2SHELL_DETECT_HOST_CRON_WEAK_SAMPLES[@]}"}")" \
            "remediation=Loop deze regels een keer na met de beheerder van de server en stel per regel vast wie hem heeft aangemaakt."
    fi
    if [ "$WP2SHELL_DETECT_HOST_CRON_STRONG_SUPPRESSED" -gt 0 ]; then
        detect_host_record_gap \
            "host-cron-truncated" \
            "Er zijn $WP2SHELL_DETECT_HOST_CRON_STRONG_SUPPRESSED kwaadaardige cronregels niet apart gerapporteerd" \
            "Het maximum van ${WP2SHELL_HOST_MAX_CRON_FINDINGS:-50} bevindingen per run is bereikt. De extra regels zijn wel aangetroffen maar staan niet afzonderlijk in dit rapport." \
            "Bekijk de crontabs van deze server handmatig, of verhoog WP2SHELL_HOST_MAX_CRON_FINDINGS en draai opnieuw."
    fi
    return 0
}

detect_host_check_cron() {
    detect_host_init_cron_patterns
    local dir path user_sources=0
    for dir in "${WP2SHELL_DETECT_HOST_USER_CRON_DIRS[@]+"${WP2SHELL_DETECT_HOST_USER_CRON_DIRS[@]}"}"; do
        if [ ! -d "$dir" ]; then
            continue
        fi
        if detect_host_scan_cron_directory "$dir" "gebruikerscrontab" 1; then
            user_sources=$((user_sources + 1))
        fi
    done
    if [ "$user_sources" -eq 0 ]; then
        detect_host_record_gap \
            "host-cron-unreadable" \
            "De crontabs van de gebruikers zijn niet gecontroleerd" \
            "Geen van de verwachte mappen ${WP2SHELL_DETECT_HOST_USER_CRON_DIRS[*]+"${WP2SHELL_DETECT_HOST_USER_CRON_DIRS[*]}"} was aanwezig en leesbaar. Persistentie via cron is de vorm die een opschoning van de sites het vaakst overleeft, dus dit onderdeel ontbreekt in deze run." \
            "Draai de hostcontroles als root, of controleer waar de cronimplementatie van deze server zijn crontabs bewaart."
    fi
    for dir in "${WP2SHELL_DETECT_HOST_SYSTEM_CRON_DIRS[@]+"${WP2SHELL_DETECT_HOST_SYSTEM_CRON_DIRS[@]}"}"; do
        detect_host_scan_cron_directory "$dir" "systeemcrontab" 1 || true
    done
    for path in "${WP2SHELL_DETECT_HOST_SYSTEM_CRON_FILES[@]+"${WP2SHELL_DETECT_HOST_SYSTEM_CRON_FILES[@]}"}"; do
        detect_host_scan_cron_file "$path" "systeemcrontab" 1
    done
    for dir in "${WP2SHELL_DETECT_HOST_SCRIPT_CRON_DIRS[@]+"${WP2SHELL_DETECT_HOST_SCRIPT_CRON_DIRS[@]}"}"; do
        detect_host_scan_cron_directory "$dir" "cronscript" 0 || true
    done
    log_info "Croncontrole klaar, $WP2SHELL_DETECT_HOST_CRON_FILES_READ bestanden gelezen uit $WP2SHELL_DETECT_HOST_CRON_SOURCES_READ bronnen"
    detect_host_report_cron_summary
    return 0
}

detect_host_preload_entry_is_structural() {
    local entry=$1
    case $entry in
        /tmp/*|/var/tmp/*|/dev/shm/*|/home/*|/var/www/*|/var/spool/*) return 0 ;;
    esac
    return 1
}

detect_host_check_ld_so_preload() {
    local path=${WP2SHELL_HOST_LD_PRELOAD_FILE:-/etc/ld.so.preload}
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        log_debug "Geen $path aanwezig, dat is het normale geval"
        return 0
    fi
    local symlink_note=''
    if [ -L "$path" ]; then
        symlink_note=' Dit bestand is bovendien een symlink, en dat is op deze plek nooit een normale opzet.'
    fi
    if [ ! -r "$path" ]; then
        detect_host_record_gap \
            "host-preload-unreadable" \
            "$path bestaat maar kon niet gelezen worden" \
            "Dit bestand laadt een gedeelde bibliotheek in elk proces op de server en is daarmee een klassieke plek voor een rootkit. De inhoud is niet beoordeeld.$symlink_note" \
            "Draai de hostcontroles als root en bekijk dit bestand handmatig." \
            "$path"
        return 0
    fi
    local size
    size=$(file_size_bytes "$path") || size=''
    case $size in
        ''|*[!0-9]*) size=0 ;;
    esac
    if [ "$size" -gt "${WP2SHELL_HOST_MAX_PRELOAD_BYTES:-65536}" ]; then
        detect_host_record_gap \
            "host-preload-unreadable" \
            "$path is ongewoon groot en is niet ingelezen" \
            "Het bestand is $size bytes groot. Een normale ld.so.preload bevat hooguit een paar paden. De inhoud is niet beoordeeld." \
            "Bekijk dit bestand handmatig." \
            "$path"
        return 0
    fi
    local line trimmed entries=0 structural=0 notes='' sample=''
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%$'\r'}
        trimmed=$(detect_host_trim_leading_space "$line")
        case $trimmed in
            ''|'#'*) continue ;;
        esac
        entries=$((entries + 1))
        if [ -n "$sample" ]; then
            sample="$sample || "
        fi
        sample="$sample$(detect_host_snippet "$trimmed")"
        if detect_host_preload_entry_is_structural "$trimmed"; then
            structural=1
            notes="$notes De opgegeven bibliotheek $trimmed staat in een map waar een systeembibliotheek niet hoort."
        fi
        if [ ! -e "$trimmed" ]; then
            notes="$notes De opgegeven bibliotheek $trimmed bestaat niet op schijf. Een verwijzing zonder bestand doet niets, dus dit kan net zo goed een restant van een verwijderd pakket zijn als een payload die is opgeruimd."
        fi
    done < "$path"
    if [ "$entries" -eq 0 ]; then
        log_debug "$path bestaat maar bevat geen actieve regels"
        return 0
    fi
    local confidence="$CONFIDENCE_HEURISTIC"
    local closing='Een beheerder kan hier legitiem een bibliotheek neerzetten, bijvoorbeeld voor een geheugenallocator of een auditmodule, en een restant van een verwijderd pakket blijft hier ook wel eens staan. Daarom staat dit op heuristisch niveau en wordt er niets automatisch veranderd.'
    if [ "$structural" = "1" ]; then
        confidence="$CONFIDENCE_HIGH"
        closing='De verwijzing wijst naar een pad dat geen legitieme systeembibliotheek kan zijn, daarom is dit als bevestigd gerapporteerd.'
    fi
    record_finding \
        "severity=$SEVERITY_CRITICAL" \
        "confidence=$confidence" \
        "category=host-ld-preload" \
        "title=$path bevat $entries actieve regel(s)" \
        "detail=Alles wat in $path staat wordt in elk proces op deze server geladen, ook in processen van andere klanten en van root. Normaal is dit bestand afwezig of leeg.$symlink_note$notes $closing" \
        "file=$path" \
        "evidence=$sample" \
        "remediation=Stel vast van welk pakket de genoemde bibliotheek komt. Hoort hij nergens bij, behandel de server dan als gecompromitteerd en herinstalleer hem, want een preload-rootkit kan alle andere controles op deze server misleiden."
    return 0
}

detect_host_key_line_summary() {
    local line=$1
    local -a fields=()
    read -r -a fields <<<"$line"
    local total=${#fields[@]}
    if [ "$total" -eq 0 ]; then
        printf 'lege regel'
        return 0
    fi
    local index=0 blob=-1
    while [ "$index" -lt "$total" ]; do
        case ${fields[$index]} in
            AAAA*) blob=$index; break ;;
        esac
        index=$((index + 1))
    done
    if [ "$blob" -lt 0 ]; then
        printf 'regel zonder herkenbaar sleutelblok'
        return 0
    fi
    local kind='onbekend type'
    if [ "$blob" -gt 0 ]; then
        kind=${fields[$((blob - 1))]}
    fi
    local comment='' index2=$((blob + 1))
    while [ "$index2" -lt "$total" ]; do
        if [ -n "$comment" ]; then
            comment="$comment "
        fi
        comment="$comment${fields[$index2]}"
        index2=$((index2 + 1))
    done
    local restricted=''
    if [ "$blob" -gt 1 ]; then
        restricted=', met opties voor de sleutel'
    fi
    if [ -z "$comment" ]; then
        comment='zonder commentaar'
    fi
    if [ "${#comment}" -gt 60 ]; then
        comment="${comment:0:60}..."
    fi
    if [ "${#kind}" -gt 30 ]; then
        kind="${kind:0:30}..."
    fi
    printf '%s (%s)%s' "$kind" "$comment" "$restricted"
    return 0
}

detect_host_check_authorized_keys_file() {
    local user=$1 path=$2
    if [ ! -e "$path" ]; then
        return 0
    fi
    if [ ! -r "$path" ]; then
        WP2SHELL_DETECT_HOST_KEY_UNREADABLE+=("$path")
        return 0
    fi
    local size
    size=$(file_size_bytes "$path") || size=''
    case $size in
        ''|*[!0-9]*) size=0 ;;
    esac
    if [ "$size" -eq 0 ]; then
        return 0
    fi
    if [ "$size" -gt "${WP2SHELL_HOST_MAX_KEY_BYTES:-262144}" ]; then
        detect_host_record_gap \
            "host-ssh-keys-unreadable" \
            "Het sleutelbestand $path is niet ingelezen" \
            "Het bestand is $size bytes groot en daarmee groter dan de limiet. De sleutels erin zijn niet geteld." \
            "Bekijk dit bestand handmatig." \
            "$path"
        return 0
    fi
    local line trimmed count=0 summary='' shown=0
    local maximum=${WP2SHELL_HOST_MAX_KEYS_SHOWN:-5}
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%$'\r'}
        trimmed=$(detect_host_trim_leading_space "$line")
        case $trimmed in
            ''|'#'*) continue ;;
        esac
        count=$((count + 1))
        if [ "$shown" -ge "$maximum" ]; then
            continue
        fi
        if [ -n "$summary" ]; then
            summary="$summary || "
        fi
        summary="$summary$(detect_host_key_line_summary "$trimmed")"
        shown=$((shown + 1))
    done < "$path"
    if [ "$count" -eq 0 ]; then
        return 0
    fi
    local key_maximum=${WP2SHELL_HOST_MAX_KEY_FINDINGS:-50}
    if [ "$WP2SHELL_DETECT_HOST_KEY_FINDINGS" -ge "$key_maximum" ]; then
        WP2SHELL_DETECT_HOST_KEY_SUPPRESSED=$((WP2SHELL_DETECT_HOST_KEY_SUPPRESSED + 1))
        return 0
    fi
    WP2SHELL_DETECT_HOST_KEY_FINDINGS=$((WP2SHELL_DETECT_HOST_KEY_FINDINGS + 1))
    local changed
    changed=$(file_mtime_iso "$path") || changed=''
    record_finding \
        "severity=$SEVERITY_INFO" \
        "confidence=$CONFIDENCE_HEURISTIC" \
        "category=host-ssh-authorized-keys" \
        "title=Gebruiker $user heeft $count SSH-sleutel(s) in authorized_keys" \
        "detail=Een toegevoegde publieke sleutel geeft blijvende toegang tot de server, ook nadat het wachtwoord is gewijzigd en de webshell is opgeruimd. Sleutels zijn tegelijk volstrekt legitiem: beheerders, backupdiensten en deploytooling gebruiken ze allemaal. Deze melding is daarom uitsluitend context, geen verdenking. Alleen het type en het commentaarveld staan hieronder, het sleutelmateriaal zelf wordt niet in het rapport opgenomen. Laatste wijziging van het bestand: ${changed:-onbekend}, en let op dat een tijdstempel te vervalsen is." \
        "file=$path" \
        "evidence=$summary" \
        "remediation=Loop deze sleutels eenmalig na met de klant en verwijder alles wat niemand herkent."
    return 0
}

detect_host_check_authorized_keys() {
    local user_list=$1
    local user home candidate
    local -a names=()
    if [ -s "$user_list" ]; then
        while IFS= read -r user || [ -n "$user" ]; do
            if [ -n "$user" ]; then
                names+=("$user")
            fi
        done < "$user_list"
    fi
    names+=("root")
    for user in "${names[@]}"; do
        home=$(detect_host_user_home "$user")
        if [ -z "$home" ]; then
            continue
        fi
        for candidate in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
            detect_host_check_authorized_keys_file "$user" "$candidate"
        done
    done
    if [ "${#WP2SHELL_DETECT_HOST_KEY_UNREADABLE[@]}" -gt 0 ]; then
        detect_host_record_gap \
            "host-ssh-keys-unreadable" \
            "${#WP2SHELL_DETECT_HOST_KEY_UNREADABLE[@]} sleutelbestanden konden niet gelezen worden" \
            "Deze authorized_keys-bestanden bestaan wel maar zijn niet leesbaar voor deze run, dus is niet vastgesteld welke sleutels er toegang geven." \
            "Draai de hostcontroles als root en beoordeel deze bestanden alsnog." \
            "$(detect_host_join_samples "${WP2SHELL_DETECT_HOST_KEY_UNREADABLE[@]}")"
    fi
    if [ "$WP2SHELL_DETECT_HOST_KEY_SUPPRESSED" -gt 0 ]; then
        detect_host_record_gap \
            "host-ssh-keys-truncated" \
            "Van $WP2SHELL_DETECT_HOST_KEY_SUPPRESSED gebruikers zijn de SSH-sleutels niet apart vermeld" \
            "Het maximum van ${WP2SHELL_HOST_MAX_KEY_FINDINGS:-50} meldingen per run is bereikt. Die gebruikers hebben wel sleutels, ze staan alleen niet afzonderlijk in dit rapport." \
            "Verhoog WP2SHELL_HOST_MAX_KEY_FINDINGS en draai opnieuw als het volledige overzicht nodig is."
    fi
    return 0
}

detect_host_collect_world_writable() {
    local base=$1 listing=$2
    local status=0
    detect_host_build_prune_arguments
    detect_host_load_prefix
    local -a prefix=()
    if [ -n "${WP2SHELL_LOAD_PREFIX[*]+x}" ]; then
        prefix=("${WP2SHELL_LOAD_PREFIX[@]}")
    fi
    : > "$listing"
    "${prefix[@]+"${prefix[@]}"}" "${WP2SHELL_FIND:-find}" -P "$base" -xdev \
        "${WP2SHELL_DETECT_HOST_PRUNE_ARGS[@]}" \
        -type d -perm -0002 -print0 > "$listing" 2>/dev/null || status=$?
    return "$status"
}

detect_host_check_world_writable() {
    local user_list=$1
    if [ ! -s "$user_list" ]; then
        return 0
    fi
    local listing
    listing=$(mktemp -t wp2shell-host-writable.XXXXXXXX) || return 1
    register_temp_cleanup "$listing"
    local maximum=${WP2SHELL_HOST_MAX_WRITABLE_SAMPLES:-25}
    local user home base status entry mode
    while IFS= read -r user || [ -n "$user" ]; do
        if [ -z "$user" ]; then
            continue
        fi
        home=$(detect_host_user_home "$user")
        base="$home/domains"
        if [ ! -d "$base" ]; then
            continue
        fi
        WP2SHELL_DETECT_HOST_WRITABLE_BASES=$((WP2SHELL_DETECT_HOST_WRITABLE_BASES + 1))
        status=0
        detect_host_collect_world_writable "$base" "$listing" || status=$?
        if [ "$status" -ne 0 ]; then
            WP2SHELL_DETECT_HOST_WRITABLE_INCOMPLETE=1
        fi
        while IFS= read -r -d '' entry; do
            WP2SHELL_DETECT_HOST_WRITABLE_COUNT=$((WP2SHELL_DETECT_HOST_WRITABLE_COUNT + 1))
            if [ "${#WP2SHELL_DETECT_HOST_WRITABLE_SAMPLES[@]}" -ge "$maximum" ]; then
                continue
            fi
            mode=$(stat -c '%a' -- "$entry" 2>/dev/null) || mode='onbekend'
            WP2SHELL_DETECT_HOST_WRITABLE_SAMPLES+=("$entry ($mode)")
        done < "$listing"
    done < "$user_list"
    rm -f -- "$listing"
    if [ "$WP2SHELL_DETECT_HOST_WRITABLE_INCOMPLETE" = "1" ]; then
        detect_host_record_gap \
            "host-world-writable-incomplete" \
            "De controle op wereldschrijfbare mappen is mogelijk onvolledig" \
            "Tijdens het doorlopen van de klantmappen waren niet alle paden leesbaar. Er kunnen wereldschrijfbare mappen gemist zijn." \
            "Draai de hostcontroles als root."
    fi
    if [ "$WP2SHELL_DETECT_HOST_WRITABLE_COUNT" -eq 0 ]; then
        log_debug "Geen wereldschrijfbare mappen gevonden in $WP2SHELL_DETECT_HOST_WRITABLE_BASES klantomgevingen"
        return 0
    fi
    record_finding \
        "severity=$SEVERITY_MEDIUM" \
        "confidence=$CONFIDENCE_HEURISTIC" \
        "category=host-world-writable-directories" \
        "title=$WP2SHELL_DETECT_HOST_WRITABLE_COUNT mappen in de klantomgevingen zijn voor iedereen schrijfbaar" \
        "detail=Een map met schrijfrecht voor iedereen kan door elke andere gebruiker op deze gedeelde server beschreven worden. Zo wordt een lek bij de ene klant een probleem bij de buren, en zo krijgt een webshell een plek om zichzelf terug te zetten. Dit is een rechteninstelling en geen besmetting: veel van deze mappen zijn ooit door een installatiehandleiding op 777 gezet. De eerste ${#WP2SHELL_DETECT_HOST_WRITABLE_SAMPLES[@]} staan hieronder met hun rechten, gebundeld in een melding omdat losse meldingen de echte vondsten uit het rapport zouden drukken." \
        "evidence=$(detect_host_join_samples "${WP2SHELL_DETECT_HOST_WRITABLE_SAMPLES[@]+"${WP2SHELL_DETECT_HOST_WRITABLE_SAMPLES[@]}"}")" \
        "remediation=Zet deze mappen terug naar 755, of naar 750 waar dat kan, en controleer daarna of de betrokken sites nog werken."
    return 0
}

detect_host_process_own_group() {
    local value
    value=$(ps -o pgid= -p "$$" 2>/dev/null) || value=''
    value=${value// /}
    printf '%s' "$value"
    return 0
}

detect_host_check_processes() {
    if [ "${WP2SHELL_HOST_SCAN_PROCESSES:-1}" != "1" ]; then
        log_debug "De proceslijst wordt niet gecontroleerd, dat staat uit in de configuratie"
        return 0
    fi
    if ! have_command ps; then
        record_finding \
            "severity=$SEVERITY_INFO" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=host-process-scan-skipped" \
            "title=De proceslijst is niet gecontroleerd" \
            "detail=Het commando ps is op deze server niet beschikbaar, dus draaiende processen zijn niet beoordeeld. Dit onderdeel is aanvullend en zwak van zichzelf, maar het uitblijven van meldingen mag niet als schoon gelezen worden." \
            "remediation=Installeer procps of controleer de proceslijst handmatig."
        return 0
    fi
    local listing status=0
    listing=$(mktemp -t wp2shell-host-ps.XXXXXXXX) || return 1
    register_temp_cleanup "$listing"
    ps -eo user:32,pid,pgid,args > "$listing" 2>/dev/null || status=$?
    if [ "$status" -ne 0 ] || [ ! -s "$listing" ]; then
        rm -f -- "$listing"
        record_finding \
            "severity=$SEVERITY_INFO" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=host-process-scan-skipped" \
            "title=De proceslijst kon niet opgevraagd worden" \
            "detail=Het commando ps gaf exitcode $status of leverde geen uitvoer. Draaiende processen zijn daardoor niet beoordeeld." \
            "remediation=Controleer de proceslijst handmatig."
        return 0
    fi
    local suspicious='(curl|wget|fetch)[^|]*\|[[:space:]]*(/[^[:space:]]*/)?(ba|z|k|da|a)?sh([[:space:]]|;|$)|(^|[^a-z0-9_/])/tmp/\.|(^|[^a-z0-9_/])/dev/shm/|xmrig|minerd|kdevtmpfsi|kinsing'
    local own='/(clamd?scan|clamd|freshclam|maldet|rkhunter|chkrootkit)([^a-z0-9_]|$)|/usr/local/maldetect/|imunify|wp2shell|clamonacc'
    local own_group
    own_group=$(detect_host_process_own_group)
    local maximum=${WP2SHELL_HOST_MAX_PROCESS_FINDINGS:-20}
    local line lowered process_user process_pid process_group remainder
    while IFS= read -r line || [ -n "$line" ]; do
        case $line in
            'USER'*) continue ;;
        esac
        read -r process_user process_pid process_group remainder <<<"$line"
        if [ -z "${remainder:-}" ]; then
            continue
        fi
        if [ -n "$own_group" ] && [ "$process_group" = "$own_group" ]; then
            continue
        fi
        if [ "$process_pid" = "$$" ] || [ "$process_pid" = "$PPID" ]; then
            continue
        fi
        lowered=${line,,}
        if [[ $lowered =~ $own ]]; then
            continue
        fi
        if ! [[ $lowered =~ $suspicious ]]; then
            continue
        fi
        if [ "$WP2SHELL_DETECT_HOST_PROCESS_FINDINGS" -ge "$maximum" ]; then
            break
        fi
        WP2SHELL_DETECT_HOST_PROCESS_FINDINGS=$((WP2SHELL_DETECT_HOST_PROCESS_FINDINGS + 1))
        record_finding \
            "severity=$SEVERITY_HIGH" \
            "confidence=$CONFIDENCE_HEURISTIC" \
            "category=host-suspicious-process" \
            "title=Verdacht proces van gebruiker $process_user" \
            "detail=Dit draaiende proces heeft een commandoregel die past bij een downloader die in een shell wordt gepijpt, bij uitvoering vanuit een tijdelijke map, of bij een van de bekende coinminers. Een proceslijst is een momentopname en een commandoregel is te vervalsen, daarom staat dit uitsluitend op heuristisch niveau. Eigen processen van deze toolkit en van de gebruikelijke scanners zijn uitgesloten, want die rommelen per definitie in verdachte paden." \
            "file=/proc/$process_pid" \
            "evidence=$(detect_host_snippet "$line")" \
            "remediation=Bekijk /proc/$process_pid/exe en /proc/$process_pid/cwd voordat het proces gestopt wordt, en zoek uit welke cronregel of welk bestand het gestart heeft."
    done < "$listing"
    rm -f -- "$listing"
    return 0
}

detect_host_reset_state() {
    WP2SHELL_DETECT_HOST_CRON_SOURCES_READ=0
    WP2SHELL_DETECT_HOST_CRON_FILES_READ=0
    WP2SHELL_DETECT_HOST_CRON_STRONG_FINDINGS=0
    WP2SHELL_DETECT_HOST_CRON_STRONG_SUPPRESSED=0
    WP2SHELL_DETECT_HOST_CRON_WEAK_COUNT=0
    WP2SHELL_DETECT_HOST_CRON_WEAK_SAMPLES=()
    WP2SHELL_DETECT_HOST_CRON_UNREADABLE=()
    WP2SHELL_DETECT_HOST_KEY_FINDINGS=0
    WP2SHELL_DETECT_HOST_KEY_SUPPRESSED=0
    WP2SHELL_DETECT_HOST_KEY_UNREADABLE=()
    WP2SHELL_DETECT_HOST_WRITABLE_COUNT=0
    WP2SHELL_DETECT_HOST_WRITABLE_SAMPLES=()
    WP2SHELL_DETECT_HOST_WRITABLE_INCOMPLETE=0
    WP2SHELL_DETECT_HOST_WRITABLE_BASES=0
    WP2SHELL_DETECT_HOST_PROCESS_FINDINGS=0
    return 0
}

detect_host_persistence() {
    if [ "${WP2SHELL_DETECT_HOST_COMPLETED:-0}" = "1" ]; then
        log_debug "De hostcontroles zijn in deze run al uitgevoerd"
        return 0
    fi
    WP2SHELL_DETECT_HOST_COMPLETED=1
    if [ "${WP2SHELL_HOST_CHECKS_ENABLED:-1}" != "1" ]; then
        detect_host_record_gap \
            "host-checks-disabled" \
            "De hostcontroles staan uit" \
            "WP2SHELL_HOST_CHECKS_ENABLED staat niet op 1, dus cron, ld.so.preload, SSH-sleutels, rechten en processen zijn deze run niet bekeken. Persistentie op serverniveau overleeft het opschonen van een site, dus dit rapport dekt die vraag niet." \
            "Zet WP2SHELL_HOST_CHECKS_ENABLED op 1 en draai de scan opnieuw."
        return 0
    fi
    detect_host_reset_state
    log_info "Hostcontroles gestart"
    detect_host_report_privilege_gap
    detect_host_check_cron || log_warn "De croncontrole is niet volledig afgerond"
    detect_host_check_ld_so_preload || log_warn "De controle op ld.so.preload is niet volledig afgerond"
    local user_list
    if ! user_list=$(mktemp -t wp2shell-host-users.XXXXXXXX); then
        detect_host_record_gap \
            "host-user-enumeration-failed" \
            "De gebruikersgebonden hostcontroles zijn niet uitgevoerd" \
            "Er kon geen tijdelijk bestand aangemaakt worden voor de gebruikerslijst. De controle op SSH-sleutels en op wereldschrijfbare mappen is daardoor overgeslagen." \
            "Controleer de schrijfrechten op de tijdelijke map en draai de scan opnieuw."
        detect_host_check_processes || log_warn "De processcan is niet volledig afgerond"
        log_info "Hostcontroles klaar"
        return 0
    fi
    register_temp_cleanup "$user_list"
    detect_host_collect_users_into "$user_list" || true
    detect_host_report_user_enumeration_source
    detect_host_check_authorized_keys "$user_list" || log_warn "De controle op SSH-sleutels is niet volledig afgerond"
    detect_host_check_world_writable "$user_list" || log_warn "De controle op wereldschrijfbare mappen is niet volledig afgerond"
    rm -f -- "$user_list"
    detect_host_check_processes || log_warn "De processcan is niet volledig afgerond"
    log_info "Hostcontroles klaar, $WP2SHELL_DETECT_HOST_CRON_FILES_READ cronbestanden en $WP2SHELL_DETECT_HOST_WRITABLE_BASES klantomgevingen beoordeeld"
    return 0
}
