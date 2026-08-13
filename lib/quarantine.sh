WP2SHELL_QUARANTINE_LOADED=1

quarantine_root_for_run() {
    printf '%s/%s' "${WP2SHELL_QUARANTINE_DIR:-/var/lib/wp2shell/quarantine}" "${WP2SHELL_RUN_ID:-onbekend}"
}

quarantine_directory_for_site() {
    printf '%s/%s' "$(quarantine_root_for_run)" "$(site_identifier "$1")"
}

quarantine_manifest_path() {
    printf '%s/manifest.ndjson' "$(quarantine_directory_for_site "$1")"
}

prepare_quarantine_directory() {
    local target_dir=$1
    if ! mkdir -p -- "$target_dir"; then
        log_error "Kan quarantainemap niet aanmaken: $target_dir"
        return 1
    fi
    chmod 0700 -- "$target_dir" 2>/dev/null || true
    return 0
}

quarantine_candidate_is_movable() {
    local file_path=$1 site_path=$2
    if [ -L "$file_path" ]; then
        log_warn "Overgeslagen, dit is een symlink en die wordt nooit verplaatst: $file_path"
        return 1
    fi
    if [ ! -f "$file_path" ]; then
        log_warn "Overgeslagen, dit is geen gewoon bestand: $file_path"
        return 1
    fi
    if ! path_is_within "$file_path" "$site_path"; then
        log_error "Overgeslagen, het pad valt buiten de installatie: $file_path"
        return 1
    fi
    return 0
}

quarantine_relative_path() {
    local file_path=$1 site_path=$2
    case $file_path in
        "$site_path"/*) printf '%s' "${file_path#"$site_path"/}" ;;
        *) printf '%s' "$(basename -- "$file_path")" ;;
    esac
}

append_quarantine_manifest_entry() {
    local manifest=$1 site_path=$2 original=$3 stored=$4 reason=$5 confidence=$6 owner=$7
    local sha1 sha256 size mtime
    sha1=$(file_sha1 "$stored") || sha1=''
    sha256=$(file_sha256 "$stored") || sha256=''
    size=$(file_size_bytes "$stored") || size=''
    mtime=$(file_mtime_iso "$stored") || mtime=''
    {
        printf '{'
        printf '"quarantined_at":%s,' "$(json_string "$(timestamp_iso)")"
        printf '"run_id":%s,' "$(json_string "${WP2SHELL_RUN_ID:-}")"
        printf '"site_path":%s,' "$(json_string "$site_path")"
        printf '"original_path":%s,' "$(json_string "$original")"
        printf '"original_path_b64":%s,' "$(json_string "$(path_to_base64 "$original")")"
        printf '"stored_path":%s,' "$(json_string "$stored")"
        printf '"stored_path_b64":%s,' "$(json_string "$(path_to_base64 "$stored")")"
        printf '"sha1":%s,' "$(json_string "$sha1")"
        printf '"sha256":%s,' "$(json_string "$sha256")"
        printf '"size_bytes":%s,' "$(json_number_or_null "$size")"
        printf '"original_mtime":%s,' "$(json_string "$mtime")"
        printf '"owner_user":%s,' "$(json_string "$owner")"
        printf '"confidence":%s,' "$(json_string "$confidence")"
        printf '"reason":%s,' "$(json_string "$reason")"
        printf '"restored":%s' "$(json_bool 0)"
        printf '}\n'
    } >> "$manifest"
    chmod 0600 -- "$manifest" 2>/dev/null || true
    return 0
}

quarantine_file() {
    local site_path=$1 file_path=$2 reason=$3 confidence=${4:-$CONFIDENCE_HIGH} owner=${5:-}
    if [ "$confidence" != "$CONFIDENCE_HIGH" ]; then
        log_error "Weigering, alleen bevestigde bevindingen mogen automatisch in quarantaine: $file_path"
        return 1
    fi
    if ! quarantine_candidate_is_movable "$file_path" "$site_path"; then
        return 1
    fi
    local target_dir relative stored stored_dir manifest
    target_dir=$(quarantine_directory_for_site "$site_path")
    relative=$(quarantine_relative_path "$file_path" "$site_path")
    stored="$target_dir/files/$relative"
    stored_dir=$(dirname -- "$stored")
    manifest=$(quarantine_manifest_path "$site_path")
    if ! prepare_quarantine_directory "$stored_dir"; then
        return 1
    fi
    if ! path_is_within "$stored_dir" "$(quarantine_root_for_run)"; then
        log_error "Weigering, het doelpad valt buiten de quarantainemap: $stored"
        return 1
    fi
    if [ -e "$stored" ]; then
        stored="$stored.$(timestamp_compact)"
    fi
    local sha1_before
    sha1_before=$(file_sha1 "$file_path") || sha1_before=''
    if ! mv -f -- "$file_path" "$stored"; then
        log_error "Verplaatsen naar quarantaine is mislukt: $file_path"
        return 1
    fi
    local sha1_after
    sha1_after=$(file_sha1 "$stored") || sha1_after=''
    if [ -n "$sha1_before" ] && [ "$sha1_before" != "$sha1_after" ]; then
        log_warn "De hash veranderde tijdens het verplaatsen van $file_path"
    fi
    append_quarantine_manifest_entry "$manifest" "$site_path" "$file_path" "$stored" "$reason" "$confidence" "$owner"
    audit_write "quarantine site=$site_path original=$file_path stored=$stored sha1=$sha1_after reason=$reason"
    log_info "In quarantaine geplaatst: $file_path"
    return 0
}

quarantine_path() {
    local site_path=$1 target=$2 reason=$3 confidence=${4:-$CONFIDENCE_HIGH} owner=${5:-}
    if [ -L "$target" ]; then
        log_warn "Overgeslagen, dit is een symlink en die wordt nooit verplaatst: $target"
        return 1
    fi
    if [ -f "$target" ]; then
        quarantine_file "$site_path" "$target" "$reason" "$confidence" "$owner"
        return $?
    fi
    if [ ! -d "$target" ]; then
        log_warn "Overgeslagen, dit is geen bestand of map: $target"
        return 1
    fi
    if ! path_is_within "$target" "$site_path"; then
        log_error "Overgeslagen, de map valt buiten de installatie: $target"
        return 1
    fi
    local listing moved=0 failed=0 entry
    listing=$(mktemp -t wp2shell-qdir.XXXXXXXX) || return 1
    register_temp_cleanup "$listing"
    "${WP2SHELL_FIND:-find}" -P "$target" -xdev -type f -print0 > "$listing" 2>/dev/null || true
    while IFS= read -r -d '' entry; do
        if quarantine_file "$site_path" "$entry" "$reason" "$confidence" "$owner"; then
            moved=$((moved + 1))
        else
            failed=$((failed + 1))
        fi
    done < "$listing"
    if [ "$moved" -gt 0 ] && [ "$failed" -eq 0 ]; then
        rmdir -p -- "$target" 2>/dev/null || true
    fi
    log_info "Map in quarantaine: $target, $moved bestanden verplaatst, $failed overgeslagen"
    if [ "$moved" -eq 0 ]; then
        return 1
    fi
    return 0
}

quarantine_report_only() {
    local site_path=$1 file_path=$2 reason=$3
    log_info "Zou in quarantaine gaan bij --apply: $file_path"
    audit_write "quarantine-dryrun site=$site_path original=$file_path reason=$reason"
    return 0
}

preview_restore_from_manifest() {
    local manifest=$1 selector=${2:-}
    if [ ! -s "$manifest" ]; then
        log_error "Geen manifest gevonden: $manifest"
        return 1
    fi
    local line original stored candidates=0
    while IFS= read -r line || [ -n "$line" ]; do
        if [ -z "$line" ]; then
            continue
        fi
        original=$(json_extract_field "$line" original_path) || original=''
        stored=$(json_extract_field "$line" stored_path) || stored=''
        if [ -z "$original" ] || [ -z "$stored" ]; then
            continue
        fi
        if [ -n "$selector" ]; then
            case $original in
                *"$selector"*) ;;
                *) continue ;;
            esac
        fi
        if [ ! -f "$stored" ]; then
            continue
        fi
        if [ -e "$original" ]; then
            continue
        fi
        candidates=$((candidates + 1))
        log_info "Zou terugzetten: $original"
    done < "$manifest"
    log_info "$candidates bestanden zouden teruggezet worden uit dit manifest"
    return 0
}

restore_from_manifest() {
    local manifest=$1 selector=${2:-}
    if [ ! -s "$manifest" ]; then
        log_error "Geen manifest gevonden: $manifest"
        return 1
    fi
    local line original stored restored_count=0 failed_count=0 skipped_count=0
    while IFS= read -r line || [ -n "$line" ]; do
        if [ -z "$line" ]; then
            continue
        fi
        original=$(json_extract_field "$line" original_path) || original=''
        stored=$(json_extract_field "$line" stored_path) || stored=''
        if [ -z "$original" ] || [ -z "$stored" ]; then
            continue
        fi
        if [ -n "$selector" ]; then
            case $original in
                *"$selector"*) ;;
                *) continue ;;
            esac
        fi
        if [ ! -f "$stored" ]; then
            if [ -e "$original" ]; then
                log_info "Stond al terug op de oorspronkelijke plek: $original"
                skipped_count=$((skipped_count + 1))
            else
                log_warn "Het bestand in quarantaine ontbreekt en staat ook niet terug: $stored"
                failed_count=$((failed_count + 1))
            fi
            continue
        fi
        if [ -e "$original" ]; then
            log_error "Niet teruggezet, er staat al een ander bestand op deze plek: $original"
            failed_count=$((failed_count + 1))
            continue
        fi
        if ! mkdir -p -- "$(dirname -- "$original")"; then
            log_error "Kan de doelmap niet aanmaken voor $original"
            failed_count=$((failed_count + 1))
            continue
        fi
        if mv -f -- "$stored" "$original"; then
            audit_write "restore original=$original stored=$stored"
            log_info "Teruggezet: $original"
            restored_count=$((restored_count + 1))
        else
            log_error "Terugzetten is mislukt: $original"
            failed_count=$((failed_count + 1))
        fi
    done < "$manifest"
    log_info "Terugzetten afgerond, $restored_count hersteld, $skipped_count overgeslagen, $failed_count mislukt"
    if [ "$failed_count" -gt 0 ]; then
        return 1
    fi
    return 0
}

quarantine_summary_for_site() {
    local site_path=$1
    local manifest
    manifest=$(quarantine_manifest_path "$site_path")
    if [ ! -s "$manifest" ]; then
        printf '0'
        return 0
    fi
    local total
    total=$("${WP2SHELL_GREP:-grep}" -c '^{' -- "$manifest" 2>/dev/null) || total=0
    case $total in
        ''|*[!0-9]*) total=0 ;;
    esac
    printf '%s' "$total"
    return 0
}
