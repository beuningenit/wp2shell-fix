WP2SHELL_CLEAN_LOADED=1

WP2SHELL_AUTO_QUARANTINE_CATEGORIES=(
    "known-malware-hash"
    "php-in-writable-directory"
    "minimal-backdoor"
    "malicious-plugin-structure"
    "wp2shell-rest-namespace"
    "user-ini-auto-prepend"
    "core-file-added"
)

category_is_auto_quarantinable() {
    local candidate=$1 entry
    for entry in "${WP2SHELL_AUTO_QUARANTINE_CATEGORIES[@]}"; do
        if [ "$entry" = "$candidate" ]; then
            return 0
        fi
    done
    return 1
}

plugin_slug_from_path() {
    local site_path=$1 candidate=$2
    if [ -z "$candidate" ]; then
        return 1
    fi
    local plugins_root="$site_path/wp-content/plugins/"
    case $candidate in
        "$plugins_root"*)
            local remainder=${candidate#"$plugins_root"}
            printf '%s' "${remainder%%/*}"
            return 0
            ;;
    esac
    return 1
}

admin_field_from_evidence() {
    local evidence=$1 field=$2
    local remainder=${evidence#*"$field" }
    if [ "$remainder" = "$evidence" ]; then
        return 1
    fi
    printf '%s' "${remainder%%,*}"
    return 0
}

maintenance_mode_activate() {
    local site_path=$1 owner_user=$2
    if wp_run "$owner_user" "$site_path" maintenance-mode activate --force >/dev/null 2>&1; then
        audit_write "maintenance site=$site_path state=on"
        return 0
    fi
    log_warn "Kon de onderhoudsmodus niet inschakelen voor $site_path"
    return 1
}

maintenance_mode_deactivate() {
    local site_path=$1 owner_user=$2
    wp_run "$owner_user" "$site_path" maintenance-mode deactivate >/dev/null 2>&1 || true
    if [ -f "$site_path/.maintenance" ] && [ ! -L "$site_path/.maintenance" ]; then
        rm -f -- "$site_path/.maintenance" 2>/dev/null || true
    fi
    audit_write "maintenance site=$site_path state=off"
    return 0
}

quarantine_findings_for_site() {
    local site_path=$1 owner_user=$2 apply=$3
    if [ ! -s "${WP2SHELL_FINDINGS_FILE:-}" ]; then
        return 0
    fi
    local snapshot
    snapshot=$(mktemp -t wp2shell-clean.XXXXXXXX)
    register_temp_cleanup "$snapshot"
    cp -- "$WP2SHELL_FINDINGS_FILE" "$snapshot"
    local line record_site confidence category file_path quarantined=0 proposed=0
    while IFS= read -r line || [ -n "$line" ]; do
        if [ -z "$line" ]; then
            continue
        fi
        record_site=$(json_extract_field "$line" site_path) || record_site=''
        if [ "$record_site" != "$site_path" ]; then
            continue
        fi
        confidence=$(json_extract_field "$line" confidence) || confidence=''
        if [ "$confidence" != "$CONFIDENCE_HIGH" ]; then
            continue
        fi
        category=$(json_extract_field "$line" category) || category=''
        if ! category_is_auto_quarantinable "$category"; then
            continue
        fi
        file_path=$(json_extract_field "$line" file_path) || file_path=''
        if [ -z "$file_path" ] || [ ! -e "$file_path" ]; then
            continue
        fi
        if is_allowlisted_path "$file_path"; then
            log_info "Op de allowlist, blijft staan: $file_path"
            continue
        fi
        if [ "$apply" != "1" ]; then
            quarantine_report_only "$site_path" "$file_path" "$category"
            proposed=$((proposed + 1))
            continue
        fi
        if quarantine_path "$site_path" "$file_path" "$category" "$CONFIDENCE_HIGH" "$owner_user"; then
            quarantined=$((quarantined + 1))
        fi
    done < "$snapshot"
    if [ "$apply" = "1" ] && [ "$quarantined" -gt 0 ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_INFO" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=cleanup-quarantined" \
            "title=$quarantined bestanden in quarantaine geplaatst" \
            "detail=Alle verplaatste bestanden staan met hun oorspronkelijke pad en hashes in het quarantainemanifest en zijn terug te zetten." \
            "action=quarantined"
    fi
    if [ "$apply" != "1" ] && [ "$proposed" -gt 0 ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_HIGH" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=cleanup-proposed" \
            "title=$proposed bestanden zouden in quarantaine gaan" \
            "detail=Er is niets gewijzigd. Deze bestanden zijn met hoge zekerheid kwaadaardig bevonden." \
            "remediation=Draai clean met --apply om ze in quarantaine te plaatsen." \
            "action=proposed"
    fi
    return 0
}

restore_core_for_site() {
    local site_path=$1 owner_user=$2 apply=$3 target_version=$4
    if [ "$apply" != "1" ]; then
        return 0
    fi
    if [ -z "$target_version" ]; then
        log_warn "Geen doelversie bekend, core wordt niet hersteld voor $site_path"
        return 0
    fi
    log_info "Core herstellen door te installeren op versie $target_version"
    if ! wp_run "$owner_user" "$site_path" core update --version="$target_version" --force >/dev/null 2>&1; then
        log_error "Core herstellen is mislukt voor $site_path"
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_HIGH" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=core-restore-failed" \
            "title=Herstellen van de WordPress-core is mislukt" \
            "detail=De core kon niet opnieuw geinstalleerd worden op versie $target_version." \
            "remediation=Herstel de core handmatig en controleer daarna opnieuw."
        return 1
    fi
    audit_write "clean core-restore site=$site_path version=$target_version"
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_INFO" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=core-restored" \
        "title=De WordPress-core is opnieuw geinstalleerd" \
        "detail=Alle corebestanden zijn overschreven met versie $target_version. Let op dat dit alleen de core betreft. Bestanden die niet in de core horen worden hier niet door verwijderd." \
        "action=applied"
    return 0
}

deactivate_malicious_plugins() {
    local site_path=$1 owner_user=$2 apply=$3
    if [ ! -s "${WP2SHELL_FINDINGS_FILE:-}" ]; then
        return 0
    fi
    local snapshot
    snapshot=$(mktemp -t wp2shell-plugins.XXXXXXXX)
    register_temp_cleanup "$snapshot"
    cp -- "$WP2SHELL_FINDINGS_FILE" "$snapshot"
    local line record_site category confidence evidence slug
    while IFS= read -r line || [ -n "$line" ]; do
        if [ -z "$line" ]; then
            continue
        fi
        record_site=$(json_extract_field "$line" site_path) || record_site=''
        if [ "$record_site" != "$site_path" ]; then
            continue
        fi
        category=$(json_extract_field "$line" category) || category=''
        confidence=$(json_extract_field "$line" confidence) || confidence=''
        case $category in
            malicious-plugin-structure|wp2shell-rest-namespace|suspicious-plugin-name) ;;
            *) continue ;;
        esac
        if [ "$confidence" != "$CONFIDENCE_HIGH" ]; then
            continue
        fi
        evidence=$(json_extract_field "$line" file_path) || evidence=''
        slug=$(plugin_slug_from_path "$site_path" "$evidence") || slug=''
        if [ -z "$slug" ]; then
            continue
        fi
        if [ "$apply" != "1" ]; then
            log_info "Zou plugin deactiveren bij --apply: $slug"
            continue
        fi
        if wp_run "$owner_user" "$site_path" plugin deactivate "$slug" >/dev/null 2>&1; then
            audit_write "clean plugin-deactivate site=$site_path plugin=$slug"
            log_info "Plugin gedeactiveerd: $slug"
        else
            log_warn "Kon plugin niet deactiveren: $slug"
        fi
    done < "$snapshot"
    return 0
}

handle_rogue_administrators() {
    local site_path=$1 owner_user=$2 apply=$3 remove_admins=$4
    if [ ! -s "${WP2SHELL_FINDINGS_FILE:-}" ]; then
        return 0
    fi
    local snapshot
    snapshot=$(mktemp -t wp2shell-admins.XXXXXXXX)
    register_temp_cleanup "$snapshot"
    cp -- "$WP2SHELL_FINDINGS_FILE" "$snapshot"
    local line record_site category evidence login user_id safe_user_id
    while IFS= read -r line || [ -n "$line" ]; do
        if [ -z "$line" ]; then
            continue
        fi
        record_site=$(json_extract_field "$line" site_path) || record_site=''
        if [ "$record_site" != "$site_path" ]; then
            continue
        fi
        category=$(json_extract_field "$line" category) || category=''
        case $category in
            admin-created-in-exposure-window|admin-not-allowlisted) ;;
            *) continue ;;
        esac
        evidence=$(json_extract_field "$line" evidence) || evidence=''
        user_id=$(admin_field_from_evidence "$evidence" "ID")
        login=$(admin_field_from_evidence "$evidence" "login")
        case $user_id in
            ''|*[!0-9]*) continue ;;
        esac
        if is_allowlisted_admin "$login" ""; then
            log_info "Adminaccount staat op de allowlist en blijft ongemoeid: $login"
            continue
        fi
        if [ "$remove_admins" != "1" ] || [ "$apply" != "1" ]; then
            record_finding \
                "site=$site_path" \
                "severity=$SEVERITY_HIGH" \
                "confidence=$CONFIDENCE_HIGH" \
                "category=admin-removal-proposed" \
                "title=Verdacht adminaccount is niet verwijderd" \
                "detail=Het account $login met id $user_id is als verdacht gemarkeerd. Accounts worden nooit automatisch verwijderd zonder de aparte vlag, want een verkeerd verwijderd account kost een klant zijn toegang." \
                "evidence=$evidence" \
                "remediation=Controleer het account en draai daarna clean met --apply en --remove-admins, of verwijder het met de hand." \
                "action=reported"
            continue
        fi
        safe_user_id=$(find_reassign_target "$site_path" "$owner_user" "$user_id")
        if [ -z "$safe_user_id" ]; then
            log_warn "Geen veilige gebruiker gevonden om content aan toe te wijzen, $login blijft staan"
            continue
        fi
        if wp_run "$owner_user" "$site_path" user delete "$user_id" --reassign="$safe_user_id" --yes >/dev/null 2>&1; then
            audit_write "clean admin-delete site=$site_path user_id=$user_id login=$login reassign=$safe_user_id"
            record_finding \
                "site=$site_path" \
                "severity=$SEVERITY_INFO" \
                "confidence=$CONFIDENCE_HIGH" \
                "category=admin-removed" \
                "title=Verdacht adminaccount verwijderd" \
                "detail=Het account $login met id $user_id is verwijderd. De content is toegewezen aan gebruiker $safe_user_id." \
                "evidence=$evidence" \
                "action=removed"
        else
            log_error "Verwijderen van adminaccount $login is mislukt"
        fi
    done < "$snapshot"
    return 0
}

find_reassign_target() {
    local site_path=$1 owner_user=$2 exclude_id=$3
    local output line candidate_id candidate_login
    output=$(wp_run "$owner_user" "$site_path" user list --role=administrator --field=ID 2>/dev/null) || return 1
    while IFS= read -r line; do
        candidate_id=${line//[!0-9]/}
        if [ -z "$candidate_id" ] || [ "$candidate_id" = "$exclude_id" ]; then
            continue
        fi
        candidate_login=$(wp_run "$owner_user" "$site_path" user get "$candidate_id" --field=user_login 2>/dev/null) || candidate_login=''
        candidate_login=${candidate_login//$'\n'/}
        if [ -n "$candidate_login" ] && is_allowlisted_admin "$candidate_login" ""; then
            printf '%s' "$candidate_id"
            return 0
        fi
    done <<< "$output"
    return 0
}

clean_injected_configuration() {
    local site_path=$1 apply=$2
    local target
    for target in "$site_path/.htaccess" "$site_path/.user.ini"; do
        if [ ! -f "$target" ] || [ -L "$target" ]; then
            continue
        fi
        if ! "${WP2SHELL_GREP:-grep}" -q 'auto_prepend_file' -- "$target" 2>/dev/null; then
            continue
        fi
        if [ "$apply" != "1" ]; then
            record_finding \
                "site=$site_path" \
                "severity=$SEVERITY_HIGH" \
                "confidence=$CONFIDENCE_HIGH" \
                "category=injected-config-proposed" \
                "title=auto_prepend_file aangetroffen in $target" \
                "detail=Met auto_prepend_file laadt de server bij elk PHP-verzoek eerst een ander bestand. Dat is een klassieke manier om een achterdeur overal actief te maken." \
                "file=$target" \
                "remediation=Draai clean met --apply, dan wordt het bestand in quarantaine gezet en vervangen." \
                "action=proposed"
            continue
        fi
        if [ "${target##*/}" = ".user.ini" ]; then
            if quarantine_file "$site_path" "$target" "auto_prepend_file in .user.ini" "$CONFIDENCE_HIGH"; then
                record_finding \
                    "site=$site_path" \
                    "severity=$SEVERITY_INFO" \
                    "confidence=$CONFIDENCE_HIGH" \
                    "category=injected-config-removed" \
                    "title=.user.ini met auto_prepend_file in quarantaine geplaatst" \
                    "detail=Het bestand is bewaard en terug te zetten." \
                    "file=$target" \
                    "action=quarantined"
            fi
        else
            record_finding \
                "site=$site_path" \
                "severity=$SEVERITY_HIGH" \
                "confidence=$CONFIDENCE_HIGH" \
                "category=injected-config-manual" \
                "title=auto_prepend_file in .htaccess vereist handmatige beoordeling" \
                "detail=De .htaccess bevat auto_prepend_file. Dit bestand bevat vrijwel altijd ook legitieme regels van de klant, dus het wordt niet automatisch vervangen." \
                "file=$target" \
                "remediation=Verwijder de auto_prepend_file-regel met de hand en controleer de rest van het bestand."
        fi
    done
    return 0
}

rerun_detection_into() {
    local site_path=$1 owner_user=$2 domain=$3 destination=$4
    local previous_findings=${WP2SHELL_FINDINGS_FILE:-}
    local failures=0 status
    : > "$destination"
    WP2SHELL_FINDINGS_FILE="$destination"
    if declare -F detect_files_for_site >/dev/null 2>&1; then
        status=0
        detect_files_for_site "$site_path" "$owner_user" >/dev/null 2>&1 || status=$?
        if [ "$status" -ne 0 ]; then
            log_error "De bestandscontrole is voortijdig gestopt met exitcode $status"
            failures=$((failures + 1))
        fi
    else
        log_error "De bestandscontrole is niet geladen"
        failures=$((failures + 1))
    fi
    if declare -F detect_wp_for_site >/dev/null 2>&1; then
        status=0
        detect_wp_for_site "$site_path" "$owner_user" "$domain" >/dev/null 2>&1 || status=$?
        if [ "$status" -ne 0 ]; then
            log_error "De WordPress-controle is voortijdig gestopt met exitcode $status"
            failures=$((failures + 1))
        fi
    else
        log_error "De WordPress-controle is niet geladen"
        failures=$((failures + 1))
    fi
    WP2SHELL_FINDINGS_FILE="$previous_findings"
    if [ "$failures" -gt 0 ]; then
        return 1
    fi
    return 0
}

verification_completeness_problems() {
    local recheck=$1 detection_status=$2
    local problems=''
    if [ "$detection_status" -ne 0 ]; then
        problems="$problems, een van de controles is voortijdig gestopt"
    fi
    if [ "${WP2SHELL_SCAN_CORE_CHECKSUMS:-1}" != "1" ]; then
        problems="$problems, de core-integriteitscontrole staat uit in de configuratie"
    fi
    if [ "${WP2SHELL_SCAN_PLUGIN_CHECKSUMS:-1}" != "1" ]; then
        problems="$problems, de plugin-integriteitscontrole staat uit in de configuratie"
    fi
    if ! "${WP2SHELL_GREP:-grep}" -q '"category":"wp-scan-scope"' -- "$recheck" 2>/dev/null; then
        problems="$problems, de WordPress-controles hebben geen afronding gemeld"
    fi
    local blind_spots
    blind_spots=$(collect_verification_blind_spots "$recheck")
    if [ -n "$blind_spots" ]; then
        problems="$problems, overgeslagen controles: $blind_spots"
    fi
    printf '%s' "${problems#, }"
    return 0
}

WP2SHELL_UNRESOLVED_COMPROMISE_CATEGORIES=(
    "core-file-modified"
    "core-restore-failed"
    "db-autoloaded-option-code"
    "db-oembed-option-code"
    "db-bridge-post-code"
    "db-siteurl-mismatch"
    "db-active-plugin-name-mismatch"
    "admin-created-in-exposure-window"
    "htaccess-auto-prepend"
    "modified-index"
    "wp-config-modified"
)

category_blocks_clean_verdict() {
    local candidate=$1 entry
    if category_is_auto_quarantinable "$candidate"; then
        return 0
    fi
    for entry in "${WP2SHELL_UNRESOLVED_COMPROMISE_CATEGORIES[@]}"; do
        if [ "$entry" = "$candidate" ]; then
            return 0
        fi
    done
    return 1
}

WP2SHELL_VERIFICATION_BLIND_CATEGORIES=(
    "wp-cli-unavailable"
    "core-checksums-unavailable"
    "core-checksums-error"
    "core-checksums-truncated"
    "core-checksums-unparsed"
    "plugin-checksums-unavailable"
    "plugin-checksums-error"
    "db-query-unavailable"
    "db-prefix-unknown"
    "db-autoload-query-failed"
    "db-bridge-posts-query-failed"
    "db-active-plugins-unavailable"
    "db-siteurl-unverified"
    "cron-list-unavailable"
    "cron-list-unparsable"
    "wp-checks-incomplete"
    "wp-config-unreadable"
    "admin-list-unavailable"
    "admin-list-unparsable"
    "ioc-data-missing"
    "scan-incomplete"
)

category_indicates_blind_spot() {
    local candidate=$1 entry
    for entry in "${WP2SHELL_VERIFICATION_BLIND_CATEGORIES[@]}"; do
        if [ "$entry" = "$candidate" ]; then
            return 0
        fi
    done
    return 1
}

collect_verification_blind_spots() {
    local findings_file=$1
    if [ ! -s "$findings_file" ]; then
        return 0
    fi
    local line category seen=''
    while IFS= read -r line || [ -n "$line" ]; do
        if [ -z "$line" ]; then
            continue
        fi
        category=$(json_extract_field "$line" category) || category=''
        if [ -z "$category" ]; then
            continue
        fi
        if ! category_indicates_blind_spot "$category"; then
            continue
        fi
        case " $seen " in
            *" $category "*) continue ;;
        esac
        seen="$seen $category"
    done < "$findings_file"
    printf '%s' "${seen# }"
    return 0
}

count_actionable_findings_in() {
    local findings_file=$1
    if [ ! -s "$findings_file" ]; then
        printf '0'
        return 0
    fi
    local line confidence category count=0
    while IFS= read -r line || [ -n "$line" ]; do
        if [ -z "$line" ]; then
            continue
        fi
        confidence=$(json_extract_field "$line" confidence) || confidence=''
        if [ "$confidence" != "$CONFIDENCE_HIGH" ]; then
            continue
        fi
        category=$(json_extract_field "$line" category) || category=''
        if category_blocks_clean_verdict "$category"; then
            count=$((count + 1))
        fi
    done < "$findings_file"
    printf '%s' "$count"
    return 0
}

verify_site_after_clean() {
    local site_path=$1 owner_user=$2 domain=$3
    local recheck remaining
    recheck=$(mktemp -t wp2shell-verify.XXXXXXXX) || return 1
    register_temp_cleanup "$recheck"
    log_info "Controle na het opschonen van $site_path"
    local detection_status=0
    rerun_detection_into "$site_path" "$owner_user" "$domain" "$recheck" || detection_status=$?
    remaining=$(count_actionable_findings_in "$recheck")
    local completeness_problems
    completeness_problems=$(verification_completeness_problems "$recheck" "$detection_status")
    if [ "$remaining" = "0" ] && [ -n "$completeness_problems" ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_HIGH" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=cleanup-unverified" \
            "title=Deze installatie kon na het opschonen niet volledig gecontroleerd worden" \
            "detail=De controle na het opschonen vond geen resterende besmetting, maar leverde ook geen bewijs dat er volledig gekeken is. Wat er ontbrak: $completeness_problems. Daardoor kan een gewijzigd corebestand, een aanpassing in de database of een achtergebleven beheerdersaccount onopgemerkt zijn gebleven. Deze site telt niet als aantoonbaar schoon, want niets vinden omdat er niet gekeken is, is geen schone site." \
            "evidence=$completeness_problems" \
            "remediation=Zorg dat WP-CLI de site kan benaderen, dat de database bereikbaar is en dat de integriteitscontroles aan staan in de configuratie, en draai daarna opnieuw clean of scan op deze installatie."
        log_error "Controle onvolledig op $site_path: $completeness_problems"
        return 1
    fi
    if [ "$remaining" = "0" ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_INFO" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=cleanup-verified" \
            "title=Na het opschonen zijn er geen bevestigde besmettingen meer gevonden" \
            "detail=Deze installatie is na het opschonen opnieuw gescand en er staan geen bestanden meer op die met hoge zekerheid kwaadaardig zijn. Dat betekent niet automatisch dat de site veilig is: als deze site tijdens het kwetsbare venster bereikbaar was, kunnen inloggegevens al uitgelezen zijn en moeten die met de hand vervangen worden." \
            "action=verified"
        log_info "Controle geslaagd, geen bevestigde besmettingen meer op $site_path"
        return 0
    fi
    local line file_path category
    while IFS= read -r line || [ -n "$line" ]; do
        if [ -z "$line" ]; then
            continue
        fi
        if [ "$(json_extract_field "$line" confidence)" != "$CONFIDENCE_HIGH" ]; then
            continue
        fi
        category=$(json_extract_field "$line" category) || category=''
        if ! category_blocks_clean_verdict "$category"; then
            continue
        fi
        file_path=$(json_extract_field "$line" file_path) || file_path=''
        local item_title item_detail item_remediation
        if category_is_auto_quarantinable "$category"; then
            item_title="Dit artefact staat er na het opschonen nog steeds"
            item_detail="Na het opschonen is deze installatie opnieuw gescand en dit artefact is opnieuw gevonden. Het is dus niet in quarantaine geplaatst, bijvoorbeeld door ontbrekende rechten, of het is opnieuw aangemaakt door iets dat nog actief is."
            item_remediation="Onderzoek dit artefact met de hand. Wordt het opnieuw aangemaakt, dan draait er nog een proces of een taak die eerst gestopt moet worden."
        else
            item_title="Deze compromittering is na het opschonen niet opgelost"
            item_detail="Na het opschonen is deze installatie opnieuw gescand en deze bevinding staat er nog. Het gaat om een categorie die niet met quarantaine wordt opgelost, zoals een gewijzigd corebestand of een aanpassing in de database. Als het herstellen van de core is mislukt of niet kon draaien, blijft de injectie gewoon staan."
            item_remediation="Herstel de core handmatig met de exacte versie, of werk de betrokken database-instelling bij, en controleer daarna opnieuw."
        fi
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_CRITICAL" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=cleanup-incomplete-item" \
            "title=$item_title" \
            "detail=$item_detail" \
            "file=$file_path" \
            "evidence=$category" \
            "remediation=$item_remediation"
    done < "$recheck"
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_CRITICAL" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=cleanup-incomplete" \
        "title=Deze installatie is na het opschonen nog niet schoon" \
        "detail=Er zijn na het opschonen nog $remaining bevestigde artefacten aanwezig. Deze site mag niet als opgeschoond beschouwd worden." \
        "remediation=Behandel deze site met voorrang handmatig."
    log_error "Controle mislukt, $remaining bevestigde artefacten blijven staan op $site_path"
    return 1
}

clean_site() {
    local site_path=$1 owner_user=$2 apply=$3 remove_admins=$4 maintenance=$5 target_version=$6
    local domain=${7:-}
    log_info "Opschonen van $site_path"
    if [ "$apply" = "1" ]; then
        if ! ensure_backup_before_changes "$site_path" "$owner_user"; then
            return 1
        fi
        if [ "$maintenance" = "1" ]; then
            maintenance_mode_activate "$site_path" "$owner_user" || true
        fi
    fi
    restore_core_for_site "$site_path" "$owner_user" "$apply" "$target_version" || true
    deactivate_malicious_plugins "$site_path" "$owner_user" "$apply" || true
    quarantine_findings_for_site "$site_path" "$owner_user" "$apply" || true
    handle_rogue_administrators "$site_path" "$owner_user" "$apply" "$remove_admins" || true
    clean_injected_configuration "$site_path" "$apply" || true
    local verification_status=0
    if [ "$apply" = "1" ]; then
        verify_site_after_clean "$site_path" "$owner_user" "$domain" || verification_status=1
    fi
    if [ "$apply" = "1" ] && [ "$maintenance" = "1" ]; then
        maintenance_mode_deactivate "$site_path" "$owner_user"
    fi
    if [ "$apply" = "1" ]; then
        report_manual_credential_rotation "$site_path"
    fi
    if [ "$verification_status" != "0" ]; then
        return 1
    fi
    return 0
}
