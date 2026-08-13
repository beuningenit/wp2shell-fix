WP2SHELL_BACKUP_LOADED=1

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

prepare_backup_directory() {
    local backup_dir=$1
    if ! mkdir -p -- "$backup_dir"; then
        log_error "Kan backupmap niet aanmaken: $backup_dir"
        return 1
    fi
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
    log_info "Backup van bestanden voor $site_path"
    if ! backup_files_archive "$site_path" "$archive"; then
        return 1
    fi
    if ! verify_files_archive "$archive"; then
        return 1
    fi
    log_info "Backup van database voor $site_path"
    if ! backup_database_dump "$site_path" "$owner_user" "$dump"; then
        return 1
    fi
    if ! verify_database_dump "$dump"; then
        return 1
    fi
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
