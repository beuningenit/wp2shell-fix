WP2SHELL_BACKUP_LOADED=1
WP2SHELL_BACKUP_RESERVED_DIRECTORY=""
WP2SHELL_BACKUP_RESERVATION_SHORTFALL=0

backup_root_for_run() {
    printf '%s/%s' "${WP2SHELL_BACKUP_DIR:-/var/backups/wp2shell}" "${WP2SHELL_RUN_ID:-onbekend}"
}

backup_directory_for_site() {
    local site_path=$1
    printf '%s/%s' "$(backup_root_for_run)" "$(site_identifier "$site_path")"
}

backup_location_is_safe() {
    local backup_dir=$1 site_path=$2
    if path_is_within "$backup_dir" "$site_path"; then
        log_error "De backupmap ligt binnen de docroot en zou publiek benaderbaar zijn: $backup_dir"
        return 1
    fi
    local home_base=${WP2SHELL_HOME_BASE:-/home}
    case $backup_dir in
        "$home_base"/*)
            log_error "De backupmap ligt in een gebruikershome en is daarmee mogelijk publiek benaderbaar: $backup_dir"
            return 1
            ;;
    esac
    return 0
}

backup_run_marker_name() {
    printf '.wp2shell-run'
    return 0
}

write_backup_run_marker() {
    local run_root=$1 marker
    marker="$run_root/$(backup_run_marker_name)"
    if [ -f "$marker" ]; then
        return 0
    fi
    {
        printf '{'
        printf '"tool":"wp2shell",'
        printf '"run_id":%s,' "$(json_string "${WP2SHELL_RUN_ID:-}")"
        printf '"created_at":%s' "$(json_string "$(timestamp_iso)")"
        printf '}\n'
    } > "$marker" 2>/dev/null || true
    chmod 0600 -- "$marker" 2>/dev/null || true
    return 0
}

backup_reset_reservations() {
    local ledger
    ledger=$(backup_reservation_file)
    mkdir -p -- "$(dirname -- "$ledger")" 2>/dev/null || true
    : > "$ledger" 2>/dev/null || true
    WP2SHELL_BACKUP_RESERVED_DIRECTORY=""
    return 0
}

prepare_backup_directory() {
    local backup_dir=$1
    if ! mkdir -p -- "$backup_dir"; then
        log_error "Kan backupmap niet aanmaken: $backup_dir"
        return 1
    fi
    write_backup_run_marker "$(backup_root_for_run)"
    chmod 0700 -- "$backup_dir" 2>/dev/null || true
    return 0
}

backup_files_archive() {
    local site_path=$1 destination=$2
    local parent base status=0
    parent=$(dirname -- "$site_path")
    base=$(basename -- "$site_path")
    "${WP2SHELL_TAR:-tar}" \
        --create \
        --gzip \
        --file="$destination" \
        --directory="$parent" \
        --warning=no-file-changed \
        --warning=no-file-removed \
        --exclude-caches-under \
        -- "$base" || status=$?
    if [ "$status" -eq 1 ]; then
        log_warn "Enkele bestanden veranderden tijdens het archiveren, dat is normaal op een actieve site"
        status=0
    fi
    if [ "$status" -ne 0 ]; then
        log_error "Archiveren van $site_path is mislukt met exitcode $status"
        return 1
    fi
    return 0
}

verify_files_archive() {
    local archive=$1
    if [ ! -s "$archive" ]; then
        log_error "Het archief is leeg: $archive"
        return 1
    fi
    if ! "${WP2SHELL_TAR:-tar}" --list --file="$archive" >/dev/null 2>&1; then
        log_error "Het archief is niet leesbaar: $archive"
        return 1
    fi
    return 0
}

backup_database_dump() {
    local site_path=$1 owner_user=$2 destination=$3
    local probe_file probe_status=0 probe_reason
    probe_file=$(mktemp "${TMPDIR:-/tmp}/wp2shell-probe.XXXXXX") || probe_file=''
    wp_is_functional "$owner_user" "$site_path" "$probe_file" || probe_status=$?
    if [ "$probe_status" -ne 0 ]; then
        probe_reason=$(wp_probe_failure_reason "$probe_file" "$probe_status")
        rm -f -- "$probe_file" 2>/dev/null || true
        log_error "WP-CLI kan de site niet benaderen, databasebackup is niet mogelijk: $probe_reason"
        return 1
    fi
    rm -f -- "$probe_file" 2>/dev/null || true
    if ! wp_run "$owner_user" "$site_path" db export - > "$destination" 2>/dev/null; then
        log_error "Databaseexport is mislukt voor $site_path"
        return 1
    fi
    return 0
}

verify_database_dump() {
    local dump=$1
    if [ ! -s "$dump" ]; then
        log_error "De databasedump is leeg: $dump"
        return 1
    fi
    if ! "${WP2SHELL_GREP:-grep}" -q -m1 -i 'CREATE TABLE' -- "$dump"; then
        log_error "De databasedump bevat geen CREATE TABLE en is vermoedelijk onvolledig: $dump"
        return 1
    fi
    return 0
}

write_backup_manifest() {
    local manifest=$1 site_path=$2 owner_user=$3 archive=$4 dump=$5
    {
        printf '{'
        printf '"run_id":%s,' "$(json_string "${WP2SHELL_RUN_ID:-}")"
        printf '"created_at":%s,' "$(json_string "$(timestamp_iso)")"
        printf '"site_path":%s,' "$(json_string "$site_path")"
        printf '"site_path_b64":%s,' "$(json_string "$(path_to_base64 "$site_path")")"
        printf '"site_id":%s,' "$(json_string "$(site_identifier "$site_path")")"
        printf '"owner_user":%s,' "$(json_string "$owner_user")"
        printf '"files_archive":%s,' "$(json_string "$archive")"
        printf '"files_archive_sha256":%s,' "$(json_string "$(file_sha256 "$archive")")"
        printf '"files_archive_bytes":%s,' "$(json_number_or_null "$(file_size_bytes "$archive")")"
        printf '"database_dump":%s,' "$(json_string "$dump")"
        printf '"database_dump_sha256":%s,' "$(json_string "$(file_sha256 "$dump")")"
        printf '"database_dump_bytes":%s' "$(json_number_or_null "$(file_size_bytes "$dump")")"
        printf '}\n'
    } > "$manifest"
    chmod 0600 -- "$manifest" 2>/dev/null || true
    return 0
}

discard_incomplete_backup() {
    local backup_dir=$1
    local root
    root=$(backup_root_for_run)
    if [ -z "$backup_dir" ] || [ ! -d "$backup_dir" ]; then
        return 0
    fi
    if ! path_is_lexically_within "$backup_dir" "$root"; then
        log_warn "Onvolledige backupmap ligt buiten de verwachte boom en blijft staan: $backup_dir"
        return 0
    fi
    if [ -f "$backup_dir/manifest.json" ]; then
        return 0
    fi
    local freed=0
    freed=$(du -sk -- "$backup_dir" 2>/dev/null | cut -f1) || freed=0
    case $freed in
        ''|*[!0-9]*) freed=0 ;;
    esac
    if rm -rf -- "$backup_dir" 2>/dev/null; then
        log_warn "Onvolledige backup verwijderd, dat gaf $((freed / 1024)) MB terug: $backup_dir"
        return 0
    fi
    log_error "Kon de onvolledige backup niet verwijderen: $backup_dir"
    return 1
}

backup_site_size_kilobytes() {
    local site_path=$1 size
    size=$(du -sk -- "$site_path" 2>/dev/null | cut -f1) || size=0
    case $size in
        ''|*[!0-9]*) size=0 ;;
    esac
    printf '%s' "$size"
    return 0
}

backup_database_size_kilobytes() {
    local site_path=$1 owner_user=$2 raw size
    raw=$(wp_run "$owner_user" "$site_path" db size --size_format=b 2>/dev/null) || raw=''
    raw=${raw%%$'\n'*}
    raw=${raw//[[:space:]]/}
    case $raw in
        ''|*[!0-9]*) return 1 ;;
    esac
    size=$((raw / 1024))
    printf '%s' "$size"
    return 0
}

backup_available_kilobytes() {
    local target=$1 available
    available=$(df -Pk -- "$target" 2>/dev/null | awk 'NR==2 {print $4}') || available=0
    case $available in
        ''|*[!0-9]*) available=0 ;;
    esac
    printf '%s' "$available"
    return 0
}

backup_reservation_file() {
    printf '%s/backup-reservering' "${WP2SHELL_STATE_DIR:-/var/lib/wp2shell}"
    return 0
}

backup_reservation_is_required() {
    local jobs=${WP2SHELL_PARALLEL_JOBS:-1}
    case $jobs in
        ''|*[!0-9]*) jobs=1 ;;
    esac
    if [ "$jobs" -gt 1 ]; then
        return 0
    fi
    return 1
}

backup_reservation_unavailable() {
    local reason=$1
    if backup_reservation_is_required; then
        log_error "$reason, en met gelijktijdige backups kan de vrije ruimte dan niet bewaakt worden"
        return 1
    fi
    log_warn "$reason, dat is bij sequentieel draaien geen bezwaar want er is geen tweede worker"
    return 0
}

backup_ledger_outstanding_kilobytes() {
    local ledger=$1 skip_dir=$2
    local needed dir written rest outstanding=0
    if [ ! -r "$ledger" ]; then
        printf '0'
        return 0
    fi
    while IFS=' ' read -r needed rest || [ -n "$needed" ]; do
        dir=$rest
        case $needed in
            ''|*[!0-9]*) continue ;;
        esac
        if [ -z "$dir" ] || [ "$dir" = "$skip_dir" ]; then
            continue
        fi
        written=$(du -sk -- "$dir" 2>/dev/null | cut -f1) || written=0
        case $written in
            ''|*[!0-9]*) written=0 ;;
        esac
        if [ "$written" -lt "$needed" ]; then
            outstanding=$((outstanding + needed - written))
        fi
    done < "$ledger"
    printf '%s' "$outstanding"
    return 0
}

backup_ledger_write() {
    local ledger=$1 bestaande=$2 nieuwe=$3
    local tijdelijk
    tijdelijk=$(mktemp "$ledger.XXXXXX" 2>/dev/null) || return 1
    {
        if [ -n "$bestaande" ]; then
            printf '%s\n' "$bestaande"
        fi
        if [ -n "$nieuwe" ]; then
            printf '%s\n' "$nieuwe"
        fi
    } > "$tijdelijk" 2>/dev/null || {
        rm -f -- "$tijdelijk" 2>/dev/null || true
        return 1
    }
    if ! mv -f -- "$tijdelijk" "$ledger" 2>/dev/null; then
        rm -f -- "$tijdelijk" 2>/dev/null || true
        return 1
    fi
    return 0
}

backup_ledger_without_directory() {
    local ledger=$1 skip_dir=$2
    local needed rest
    if [ ! -r "$ledger" ]; then
        return 0
    fi
    while IFS=' ' read -r needed rest || [ -n "$needed" ]; do
        case $needed in
            ''|*[!0-9]*) continue ;;
        esac
        if [ -z "$rest" ] || [ "$rest" = "$skip_dir" ]; then
            continue
        fi
        printf '%s %s\n' "$needed" "$rest"
    done < "$ledger"
    return 0
}

backup_reserve_space() {
    local needed=$1 backup_dir=$2
    local ledger lock outstanding available free overig
    ledger=$(backup_reservation_file)
    if ! mkdir -p -- "$(dirname -- "$ledger")" 2>/dev/null; then
        backup_reservation_unavailable "Kan de map voor het reserveringsgrootboek niet aanmaken"
        return $?
    fi
    lock="$ledger.lock"
    if ! exec 8>"$lock" 2>/dev/null; then
        backup_reservation_unavailable "Kan het reserveringsgrootboek niet openen"
        return $?
    fi
    if ! have_command flock; then
        exec 8>&-
        backup_reservation_unavailable "flock ontbreekt"
        return $?
    fi
    if ! flock -w 60 8; then
        exec 8>&-
        backup_reservation_unavailable "Kon het reserveringsgrootboek niet vergrendelen binnen een minuut"
        return $?
    fi
    outstanding=$(backup_ledger_outstanding_kilobytes "$ledger" "$backup_dir")
    available=$(backup_available_kilobytes "$backup_dir")
    free=$((available - outstanding))
    if [ "$free" -lt "$needed" ]; then
        flock -u 8
        exec 8>&-
        log_error "Onvoldoende ruimte na verrekening van gelijktijdige backups: $((free / 1024)) MB vrij, $((needed / 1024)) MB nodig"
        WP2SHELL_BACKUP_RESERVATION_SHORTFALL=$free
        return 2
    fi
    overig=$(backup_ledger_without_directory "$ledger" "$backup_dir")
    if ! backup_ledger_write "$ledger" "$overig" "$needed $backup_dir"; then
        flock -u 8
        exec 8>&-
        backup_reservation_unavailable "Kan het reserveringsgrootboek niet bijwerken"
        return $?
    fi
    flock -u 8
    exec 8>&-
    WP2SHELL_BACKUP_RESERVED_DIRECTORY=$backup_dir
    return 0
}

backup_release_space() {
    local backup_dir=${WP2SHELL_BACKUP_RESERVED_DIRECTORY:-}
    WP2SHELL_BACKUP_RESERVED_DIRECTORY=""
    if [ -z "$backup_dir" ]; then
        return 0
    fi
    local ledger lock overig
    ledger=$(backup_reservation_file)
    lock="$ledger.lock"
    exec 8>"$lock" 2>/dev/null || return 0
    if ! have_command flock || ! flock -w 60 8; then
        exec 8>&-
        return 0
    fi
    overig=$(backup_ledger_without_directory "$ledger" "$backup_dir")
    backup_ledger_write "$ledger" "$overig" "" || \
        log_warn "Kon het reserveringsgrootboek niet bijwerken bij het vrijgeven van $backup_dir"
    flock -u 8
    exec 8>&-
    return 0
}

backup_size_check_is_mandatory() {
    if [ "${WP2SHELL_BACKUP_REQUIRE_SIZE_CHECK:-1}" = "0" ]; then
        return 1
    fi
    return 0
}

backup_report_unmeasurable() {
    local site_path=$1 wat=$2
    if ! backup_size_check_is_mandatory; then
        log_warn "$wat kon niet vastgesteld worden voor $site_path, de backup gaat door omdat de ruimtecontrole is uitgezet"
        return 0
    fi
    log_error "$wat kon niet vastgesteld worden voor $site_path, de backup gaat niet door"
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_MEDIUM" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=backup-size-unknown" \
        "title=De benodigde ruimte voor een backup is niet vast te stellen" \
        "detail=$wat kon niet gemeten worden. Zonder die maat is niet te bepalen of de backup op de schijf past. Een backup die halverwege de schijf volschrijft raakt alle klanten op deze server, dus deze site is overgeslagen en niet gewijzigd." \
        "evidence=$wat" \
        "remediation=Controleer of du, df en wp db size werken voor deze site. Wie de backup toch wil laten doorgaan zonder deze controle, zet WP2SHELL_BACKUP_REQUIRE_SIZE_CHECK op 0 en accepteert dat risico bewust." \
        "action=skipped"
    return 1
}

backup_space_is_sufficient() {
    local site_path=$1 backup_dir=$2 owner_user=${3:-}
    local margin=${WP2SHELL_BACKUP_FREE_MARGIN_PERCENT:-30}
    case $margin in
        ''|*[!0-9]*) margin=30 ;;
    esac
    local needed available site_size database_size=0
    if ! backup_size_check_is_mandatory; then
        log_warn "De ruimtecontrole staat uit voor $site_path, de backup gaat door zonder te toetsen of hij past"
        return 0
    fi
    site_size=$(backup_site_size_kilobytes "$site_path")
    if [ "$site_size" -eq 0 ]; then
        backup_report_unmeasurable "$site_path" "De omvang van de bestanden onder de docroot"
        return $?
    fi
    available=$(backup_available_kilobytes "$backup_dir")
    if [ "$available" -eq 0 ]; then
        backup_report_unmeasurable "$site_path" "De vrije ruimte op de backupmap"
        return $?
    fi
    local database_known=1
    if [ -z "$owner_user" ] || ! database_size=$(backup_database_size_kilobytes "$site_path" "$owner_user"); then
        database_known=0
        database_size=$site_size
        log_warn "De omvang van de database is niet vast te stellen voor $site_path, er wordt gerekend met een even grote database als de bestanden"
    fi
    needed=$(((site_size + database_size) + ((site_size + database_size) * margin / 100)))
    if [ "$available" -ge "$needed" ]; then
        local reserve_status=0
        backup_reserve_space "$needed" "$backup_dir" || reserve_status=$?
        if [ "$reserve_status" -eq 0 ]; then
            return 0
        fi
        if [ "$reserve_status" -eq 2 ]; then
            record_finding \
                "site=$site_path" \
                "severity=$SEVERITY_HIGH" \
                "confidence=$CONFIDENCE_HIGH" \
                "category=backup-space-insufficient" \
                "title=Te weinig schijfruimte voor een backup" \
                "detail=Op de schijf staat genoeg vrij, maar gelijktijdig lopende backups van andere sites hebben die ruimte al nodig. Deze site is overgeslagen en niet gewijzigd, zodat de schijf niet volloopt terwijl de andere backups nog schrijven." \
                "evidence=nog vrij te vergeven $((${WP2SHELL_BACKUP_RESERVATION_SHORTFALL:-0} / 1024)) MB, nodig $((needed / 1024)) MB, ruw beschikbaar $((available / 1024)) MB" \
                "remediation=Draai deze site opnieuw als de andere backups klaar zijn, verlaag --parallel, of wijs met --backup-dir een locatie met meer ruimte aan." \
                "action=skipped"
            return 1
        fi
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=backup-reservation-unavailable" \
            "title=De ruimtereservering tussen gelijktijdige backups werkt niet" \
            "detail=Er is voldoende schijfruimte, maar het grootboek dat de behoefte van gelijktijdige workers bijhoudt kon niet aangemaakt, vergrendeld of bijgewerkt worden. Bij parallelle verwerking zouden meerdere backups dan onafhankelijk van elkaar groen krijgen en samen de schijf kunnen vullen. Deze site is daarom overgeslagen en niet gewijzigd." \
            "evidence=beschikbaar $((available / 1024)) MB, nodig $((needed / 1024)) MB, grootboek $(backup_reservation_file)" \
            "remediation=Controleer of de state-map bestaat en beschrijfbaar is en of flock beschikbaar is. Een run zonder --parallel heeft dit grootboek niet nodig." \
            "action=skipped"
        return 1
    fi
    log_error "Te weinig vrije ruimte voor een backup van $site_path: $((available / 1024)) MB beschikbaar, $((needed / 1024)) MB nodig"
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_HIGH" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=backup-space-insufficient" \
        "title=Te weinig schijfruimte voor een backup" \
        "detail=De backup is niet gestart omdat er te weinig vrije ruimte is op de doelmap. De site is daardoor niet gewijzigd. Zonder deze controle zou de backup de schijf hebben volgeschreven, wat alle klanten op deze server raakt." \
        "evidence=beschikbaar $((available / 1024)) MB, nodig $((needed / 1024)) MB inclusief een marge van $margin procent, bestanden $((site_size / 1024)) MB, database $((database_size / 1024)) MB$([ "$database_known" = "1" ] || printf ' (geschat, de werkelijke omvang was niet op te vragen)')" \
        "remediation=Ruim oude backups op met tools/prune-backups.sh of wijs met --backup-dir een locatie met meer ruimte aan." \
        "action=skipped"
    return 1
}

backup_site() {
    local site_path=$1 owner_user=$2
    local backup_dir archive dump manifest
    backup_dir=$(backup_directory_for_site "$site_path")
    if ! backup_location_is_safe "$backup_dir" "$site_path"; then
        return 1
    fi
    if [ -f "$backup_dir/manifest.json" ]; then
        log_info "Er bestaat al een backup voor deze site in deze run, die wordt hergebruikt"
        WP2SHELL_LAST_BACKUP_DIR="$backup_dir"
        return 0
    fi
    if ! prepare_backup_directory "$backup_dir"; then
        return 1
    fi
    archive="$backup_dir/files.tar.gz"
    dump="$backup_dir/database.sql"
    manifest="$backup_dir/manifest.json"
    if ! backup_space_is_sufficient "$site_path" "$backup_dir" "$owner_user"; then
        discard_incomplete_backup "$backup_dir"
        return 1
    fi
    log_info "Backup van bestanden voor $site_path"
    if ! backup_files_archive "$site_path" "$archive"; then
        backup_release_space
        discard_incomplete_backup "$backup_dir"
        return 1
    fi
    if ! verify_files_archive "$archive"; then
        backup_release_space
        discard_incomplete_backup "$backup_dir"
        return 1
    fi
    log_info "Backup van database voor $site_path"
    if ! backup_database_dump "$site_path" "$owner_user" "$dump"; then
        backup_release_space
        discard_incomplete_backup "$backup_dir"
        return 1
    fi
    if ! verify_database_dump "$dump"; then
        backup_release_space
        discard_incomplete_backup "$backup_dir"
        return 1
    fi
    backup_release_space
    write_backup_manifest "$manifest" "$site_path" "$owner_user" "$archive" "$dump"
    chmod 0600 -- "$archive" "$dump" 2>/dev/null || true
    WP2SHELL_LAST_BACKUP_DIR="$backup_dir"
    audit_write "backup site=$site_path user=$owner_user dir=$backup_dir archive_sha256=$(file_sha256 "$archive")"
    log_info "Backup voltooid in $backup_dir"
    return 0
}

ensure_backup_before_changes() {
    local site_path=$1 owner_user=$2
    if backup_site "$site_path" "$owner_user"; then
        return 0
    fi
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_HIGH" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=backup-failed" \
        "title=Backup is mislukt, deze site is overgeslagen" \
        "detail=Er kon geen volledige backup van bestanden en database gemaakt worden. Er is daarom niets gewijzigd aan deze site. Zonder herstelpunt wordt er niet opgeschoond." \
        "remediation=Onderzoek waarom de backup mislukt, bijvoorbeeld schijfruimte of een onbereikbare database, en draai daarna opnieuw." \
        "action=skipped"
    log_error "Backup mislukt voor $site_path, deze site wordt overgeslagen"
    return 1
}
