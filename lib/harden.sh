WP2SHELL_HARDEN_LOADED=1

WP2SHELL_HTACCESS_BEGIN="# BEGIN wp2shell-hardening"
WP2SHELL_HTACCESS_END="# END wp2shell-hardening"
WP2SHELL_HARDENING_PROBE_PATH="wp2shell-hardening-active"
WP2SHELL_RESTART_REQUIRED=0

docroot_htaccess_payload() {
    printf '%s\n' "$WP2SHELL_HTACCESS_BEGIN"
    printf 'RewriteEngine On\n'
    printf 'RewriteRule ^/?%s$ - [F,L,NC]\n' "$WP2SHELL_HARDENING_PROBE_PATH"
    printf 'RewriteRule ^/?wp-content/(?:uploads|cache)/.*\\.(?:php|php[0-9]+|phtml|phps|pht|phar|shtml|cgi|pl)(?:/|$) - [F,L,NC]\n'
    printf 'RewriteRule ^/?(?:wp-config\\.php|wp-config-sample\\.php|readme\\.html|license\\.txt)$ - [F,L,NC]\n'
    printf 'RewriteRule (?:^|/)\\.user\\.ini$ - [F,L,NC]\n'
    printf 'RewriteRule (?:^|/)(?:debug\\.log|error_log)$ - [F,L,NC]\n'
    if [ "${WP2SHELL_HARDEN_BLOCK_XMLRPC:-0}" = "1" ]; then
        printf 'RewriteRule ^/?xmlrpc\\.php$ - [F,L,NC]\n'
    fi
    printf '%s\n' "$WP2SHELL_HTACCESS_END"
    return 0
}

writable_directory_htaccess_payload() {
    printf '%s\n' "$WP2SHELL_HTACCESS_BEGIN"
    printf 'RewriteEngine On\n'
    printf 'RewriteRule ^/?.*\\.(?:php|php[0-9]+|phtml|phps|pht|phar|shtml|cgi|pl)(?:/|$) - [F,L,NC]\n'
    printf '%s\n' "$WP2SHELL_HTACCESS_END"
    return 0
}

strip_existing_hardening_block() {
    local source_file=$1
    if [ ! -f "$source_file" ]; then
        return 0
    fi
    awk -v begin="$WP2SHELL_HTACCESS_BEGIN" -v end="$WP2SHELL_HTACCESS_END" '
        $0 == begin { inside = 1; next }
        $0 == end { inside = 0; next }
        inside != 1 { print }
    ' "$source_file"
    return 0
}

write_htaccess_with_block() {
    local target=$1 payload_function=$2
    local target_dir remainder temp_file
    target_dir=$(dirname -- "$target")
    if [ ! -d "$target_dir" ]; then
        return 1
    fi
    remainder=$(strip_existing_hardening_block "$target")
    temp_file=$(mktemp "$target_dir/.wp2shell-htaccess.XXXXXXXX") || return 1
    {
        "$payload_function"
        if [ -n "$remainder" ]; then
            printf '%s\n' "$remainder"
        fi
    } > "$temp_file"
    if [ -f "$target" ]; then
        chmod --reference="$target" -- "$temp_file" 2>/dev/null || chmod 0644 -- "$temp_file"
        chown --reference="$target" -- "$temp_file" 2>/dev/null || true
    else
        chmod 0644 -- "$temp_file"
    fi
    if ! mv -f -- "$temp_file" "$target"; then
        rm -f -- "$temp_file"
        return 1
    fi
    return 0
}

htaccess_block_is_current() {
    local target=$1
    if [ ! -f "$target" ]; then
        return 1
    fi
    local existing expected
    existing=$(awk -v begin="$WP2SHELL_HTACCESS_BEGIN" -v end="$WP2SHELL_HTACCESS_END" '
        $0 == begin { inside = 1 }
        inside == 1 { print }
        $0 == end { inside = 0 }
    ' "$target")
    expected=$(docroot_htaccess_payload)
    [ "$existing" = "$expected" ]
}

capture_existing_htaccess_as_evidence() {
    local site_path=$1 target=$2
    if [ ! -f "$target" ]; then
        return 0
    fi
    if ! "${WP2SHELL_GREP:-grep}" -qiE 'rewrite|auto_prepend|php_value|addhandler' -- "$target" 2>/dev/null; then
        return 0
    fi
    if "${WP2SHELL_GREP:-grep}" -qF "$WP2SHELL_HTACCESS_BEGIN" -- "$target" 2>/dev/null; then
        return 0
    fi
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_MEDIUM" \
        "confidence=$CONFIDENCE_HEURISTIC" \
        "category=pre-existing-htaccess" \
        "title=Er stond al een .htaccess met regels in een schrijfbare map" \
        "detail=Voor het toepassen van de hardening stond hier al een .htaccess met rewrite- of handlerdirectieven. Dat kan legitiem maatwerk zijn, maar het kan ook een omzeiling van de blokkade of een artefact van de aanvaller zijn." \
        "file=$target" \
        "sha1=$(file_sha1 "$target")" \
        "remediation=Beoordeel de oorspronkelijke inhoud, die is bewaard in de backup van deze run."
    return 0
}

harden_htaccess_for_site() {
    local site_path=$1 apply=$2
    local docroot_htaccess="$site_path/.htaccess"
    local changed=0
    if [ "$apply" != "1" ]; then
        if ! htaccess_block_is_current "$docroot_htaccess"; then
            record_finding \
                "site=$site_path" \
                "severity=$SEVERITY_MEDIUM" \
                "confidence=$CONFIDENCE_HIGH" \
                "category=hardening-missing" \
                "title=De hardeningregels in .htaccess ontbreken of zijn verouderd" \
                "detail=Er zijn geen actuele wp2shell-hardeningregels aanwezig. Die blokkeren het direct uitvoeren van PHP in wp-content/uploads en wp-content/cache en beschermen gevoelige bestanden." \
                "file=$docroot_htaccess" \
                "remediation=Draai harden met --apply." \
                "action=proposed"
        fi
        return 0
    fi
    capture_existing_htaccess_as_evidence "$site_path" "$docroot_htaccess"
    if ! htaccess_block_is_current "$docroot_htaccess"; then
        if write_htaccess_with_block "$docroot_htaccess" docroot_htaccess_payload; then
            audit_write "harden htaccess site=$site_path file=$docroot_htaccess"
            changed=1
        else
            log_error "Kon .htaccess niet schrijven voor $site_path"
            return 1
        fi
    fi
    local writable_dir
    for writable_dir in "$site_path/wp-content/uploads" "$site_path/wp-content/cache"; do
        if [ -d "$writable_dir" ]; then
            capture_existing_htaccess_as_evidence "$site_path" "$writable_dir/.htaccess"
            if write_htaccess_with_block "$writable_dir/.htaccess" writable_directory_htaccess_payload; then
                audit_write "harden htaccess site=$site_path file=$writable_dir/.htaccess"
                changed=1
            fi
        fi
    done
    if [ "$changed" = "1" ]; then
        WP2SHELL_RESTART_REQUIRED=1
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_INFO" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=hardening-applied" \
            "title=Hardeningregels in .htaccess geschreven" \
            "detail=De regels zijn weggeschreven. OpenLiteSpeed leest .htaccess eenmalig bij het laden van de configuratie, dus ze worden pas van kracht na een herstart van de webserver." \
            "remediation=De herstart en de verificatie gebeuren aan het eind van deze run." \
            "action=applied"
    fi
    return 0
}

openlitespeed_control_binary() {
    local candidate
    for candidate in /usr/local/lsws/bin/lswsctrl /usr/local/lsws/admin/misc/lswsctrl; do
        if [ -x "$candidate" ]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

restart_openlitespeed_if_needed() {
    local apply=$1
    if [ "$WP2SHELL_RESTART_REQUIRED" != "1" ]; then
        return 0
    fi
    if [ "$apply" != "1" ]; then
        log_info "Zonder --apply wordt de webserver niet herstart"
        return 0
    fi
    local control
    if ! control=$(openlitespeed_control_binary); then
        log_warn "lswsctrl niet gevonden, herstart de webserver handmatig zodat de regels van kracht worden"
        record_finding \
            "severity=$SEVERITY_HIGH" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=restart-required" \
            "title=De webserver moet handmatig herstart worden" \
            "detail=De hardeningregels zijn geschreven maar OpenLiteSpeed kon niet automatisch herstart worden. Tot die herstart doen de regels niets, want OpenLiteSpeed leest .htaccess alleen bij het laden van de configuratie." \
            "remediation=Draai /usr/local/lsws/bin/lswsctrl restart en controleer daarna de sites."
        return 1
    fi
    log_info "OpenLiteSpeed wordt herstart zodat de hardeningregels van kracht worden"
    if "$control" restart >/dev/null 2>&1; then
        audit_write "restart webserver=openlitespeed result=ok"
        log_info "OpenLiteSpeed is herstart"
        return 0
    fi
    audit_write "restart webserver=openlitespeed result=failed"
    log_error "Herstarten van OpenLiteSpeed is mislukt"
    return 1
}

verify_hardening_enforced() {
    local site_path=$1 url=$2
    if [ -z "$url" ]; then
        return 0
    fi
    local probe_url="${url%/}/$WP2SHELL_HARDENING_PROBE_PATH"
    local status
    status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 15 -k -- "$probe_url" 2>/dev/null) || status=''
    case $status in
        403)
            log_info "Hardening is actief op $url"
            record_finding \
                "site=$site_path" \
                "severity=$SEVERITY_INFO" \
                "confidence=$CONFIDENCE_HIGH" \
                "category=hardening-enforced" \
                "title=De hardeningregels worden daadwerkelijk afgedwongen" \
                "detail=De controle op $probe_url gaf 403, wat bewijst dat OpenLiteSpeed de .htaccess van deze vhost leest en de regels toepast." \
                "action=verified"
            return 0
            ;;
        404)
            record_finding \
                "site=$site_path" \
                "severity=$SEVERITY_HIGH" \
                "confidence=$CONFIDENCE_HIGH" \
                "category=hardening-not-enforced" \
                "title=De hardeningregels staan er wel maar worden niet afgedwongen" \
                "detail=De controle op $probe_url gaf 404 in plaats van 403. OpenLiteSpeed leest de .htaccess van deze vhost niet, waarschijnlijk omdat rewrite of het automatisch laden van .htaccess uit staat. De regels bieden hier dus geen bescherming." \
                "remediation=Zet Enable Rewrite en Auto Load from .htaccess aan voor deze vhost en controleer daarna opnieuw."
            return 1
            ;;
        *)
            record_finding \
                "site=$site_path" \
                "severity=$SEVERITY_MEDIUM" \
                "confidence=$CONFIDENCE_HEURISTIC" \
                "category=hardening-unverified" \
                "title=Kon niet vaststellen of de hardening actief is" \
                "detail=De controle op $probe_url leverde status ${status:-geen antwoord}. Dat zegt niets over de regels zelf, maar de bescherming is niet bevestigd." \
                "remediation=Controleer handmatig of de site bereikbaar is en herhaal de verificatie."
            return 1
            ;;
    esac
}

harden_wp_configuration() {
    local site_path=$1 owner_user=$2 apply=$3
    local config_file="$site_path/wp-config.php"
    if [ ! -f "$config_file" ]; then
        return 0
    fi
    local needs_file_edit=0
    if ! "${WP2SHELL_GREP:-grep}" -qE "define\s*\(\s*['\"]DISALLOW_FILE_EDIT['\"]" -- "$config_file" 2>/dev/null; then
        needs_file_edit=1
    fi
    if [ "$needs_file_edit" = "1" ]; then
        if [ "$apply" != "1" ]; then
            record_finding \
                "site=$site_path" \
                "severity=$SEVERITY_LOW" \
                "confidence=$CONFIDENCE_HIGH" \
                "category=hardening-missing" \
                "title=DISALLOW_FILE_EDIT staat niet aan" \
                "detail=Zonder deze constante kan een aanvaller met een adminaccount via de ingebouwde editor direct PHP-code in het thema of een plugin schrijven." \
                "remediation=Draai harden met --apply." \
                "action=proposed"
        else
            if wp_run "$owner_user" "$site_path" config set DISALLOW_FILE_EDIT true --raw --type=constant >/dev/null 2>&1; then
                audit_write "harden config site=$site_path constant=DISALLOW_FILE_EDIT"
                log_info "DISALLOW_FILE_EDIT gezet voor $site_path"
            else
                log_warn "Kon DISALLOW_FILE_EDIT niet zetten voor $site_path"
            fi
        fi
    fi
    local auto_update_blocked=0
    if "${WP2SHELL_GREP:-grep}" -qE "define\s*\(\s*['\"](AUTOMATIC_UPDATER_DISABLED|DISALLOW_FILE_MODS)['\"]\s*,\s*true" -- "$config_file" 2>/dev/null; then
        auto_update_blocked=1
    fi
    if "${WP2SHELL_GREP:-grep}" -qE "define\s*\(\s*['\"]WP_AUTO_UPDATE_CORE['\"]\s*,\s*false" -- "$config_file" 2>/dev/null; then
        auto_update_blocked=1
    fi
    if [ "$auto_update_blocked" = "1" ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_HIGH" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=auto-updates-blocked" \
            "title=Automatische core-updates zijn geblokkeerd in wp-config.php" \
            "detail=Deze site ontving de geforceerde beveiligingsupdate van WordPress niet, omdat AUTOMATIC_UPDATER_DISABLED, DISALLOW_FILE_MODS of WP_AUTO_UPDATE_CORE dat tegenhoudt. Juist deze sites stonden het langst bloot." \
            "file=$config_file" \
            "remediation=Haal de blokkade weg zodat beveiligingsreleases voortaan automatisch landen, en werk deze site met voorrang bij."
    fi
    return 0
}

rotate_salts_for_site() {
    local site_path=$1 owner_user=$2 apply=$3 exposed=$4
    if [ "$exposed" != "1" ]; then
        return 0
    fi
    if [ "$apply" != "1" ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_HIGH" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=salts-rotation-needed" \
            "title=De salts en keys moeten vervangen worden" \
            "detail=Deze site stond bloot tijdens het kwetsbare venster. Een aanvaller die wp-config.php heeft uitgelezen kent de salts en kan daarmee sessies vervalsen." \
            "remediation=Draai harden met --apply, dan worden de salts vervangen en worden alle sessies ongeldig." \
            "action=proposed"
        return 0
    fi
    if wp_run "$owner_user" "$site_path" config shuffle-salts >/dev/null 2>&1; then
        audit_write "harden salts site=$site_path result=ok"
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_INFO" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=salts-rotated" \
            "title=Salts en keys zijn vervangen" \
            "detail=Alle bestaande sessies en inlogcookies zijn hiermee ongeldig geworden. Gebruikers moeten opnieuw inloggen." \
            "action=applied"
        return 0
    fi
    log_warn "Vervangen van de salts is mislukt voor $site_path"
    return 1
}

report_manual_credential_rotation() {
    local site_path=$1
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_HIGH" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=manual-credential-rotation" \
        "title=Deze wachtwoorden moet een mens zelf vervangen" \
        "detail=Bij een bevestigde of vermoede compromittering is wp-config.php uitleesbaar geweest, inclusief de databasegegevens en de API-sleutels die daarin staan. Dit script vervangt die bewust niet, want het kan geen nieuwe waarden in panelen invoeren." \
        "remediation=Vervang met de hand: het databasewachtwoord, de DirectAdmin-login van deze klant, FTP- en SSH-toegang, en elke API-sleutel die in wp-config.php stond. Forceer daarnaast een wachtwoordreset voor alle beheerders."
    return 0
}

normalize_permissions_for_site() {
    local site_path=$1 owner_user=$2 apply=$3
    if [ "$apply" != "1" ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_LOW" \
            "confidence=$CONFIDENCE_HEURISTIC" \
            "category=permissions" \
            "title=Bestandsrechten zijn niet genormaliseerd" \
            "detail=Met --apply worden mappen op 755 gezet, bestanden op 644 en wp-config.php op 640, met de juiste eigenaar." \
            "remediation=Draai harden met --apply." \
            "action=proposed"
        return 0
    fi
    if ! user_exists "$owner_user"; then
        log_warn "Gebruiker $owner_user bestaat niet, rechten worden niet aangepast voor $site_path"
        return 1
    fi
    local group
    group=$(id -gn "$owner_user" 2>/dev/null) || group="$owner_user"
    chown -R --no-dereference -- "$owner_user:$group" "$site_path" 2>/dev/null || \
        log_warn "Kon eigendom niet volledig aanpassen voor $site_path"
    find_and_chmod_directories "$site_path"
    find_and_chmod_files "$site_path"
    if [ -f "$site_path/wp-config.php" ] && [ ! -L "$site_path/wp-config.php" ]; then
        chmod 0640 -- "$site_path/wp-config.php" 2>/dev/null || true
    fi
    audit_write "harden permissions site=$site_path owner=$owner_user"
    return 0
}

find_and_chmod_directories() {
    local site_path=$1
    "${WP2SHELL_FIND:-find}" -P "$site_path" -xdev -type d -exec chmod 0755 {} + 2>/dev/null || true
    return 0
}

find_and_chmod_files() {
    local site_path=$1
    "${WP2SHELL_FIND:-find}" -P "$site_path" -xdev -type f -exec chmod 0644 {} + 2>/dev/null || true
    return 0
}

update_core_for_site() {
    local site_path=$1 owner_user=$2 apply=$3 target_version=$4
    if [ -z "$target_version" ]; then
        return 0
    fi
    if [ "$apply" != "1" ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_HIGH" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=update-needed" \
            "title=WordPress moet bijgewerkt worden naar $target_version" \
            "detail=Bijwerken is de eigenlijke oplossing. Alle andere maatregelen zijn aanvullend." \
            "remediation=Draai harden met --apply." \
            "action=proposed"
        return 0
    fi
    log_info "Bijwerken van $site_path naar $target_version"
    if ! wp_run "$owner_user" "$site_path" core update --version="$target_version" --force >/dev/null 2>&1; then
        log_error "Bijwerken naar $target_version is mislukt voor $site_path"
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_HIGH" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=update-failed" \
            "title=Bijwerken van de WordPress-core is mislukt" \
            "detail=De update naar $target_version kon niet uitgevoerd worden." \
            "remediation=Onderzoek de oorzaak en werk deze site met voorrang handmatig bij."
        return 1
    fi
    local new_version
    new_version=$(wp_run "$owner_user" "$site_path" core version 2>/dev/null) || new_version=''
    new_version=${new_version//$'\n'/}
    audit_write "harden core-update site=$site_path from_target=$target_version result=$new_version"
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_INFO" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=updated" \
        "title=WordPress is bijgewerkt" \
        "detail=De core draait nu versie ${new_version:-onbekend}. Bijwerken verwijdert geen achterdeur die er al stond." \
        "action=applied"
    return 0
}

softaculous_cli_path() {
    local candidate=/usr/local/directadmin/plugins/softaculous/cli.php
    if [ -r "$candidate" ]; then
        printf '%s' "$candidate"
        return 0
    fi
    return 1
}

enable_softaculous_auto_upgrade() {
    local apply=$1
    local cli
    if ! cli=$(softaculous_cli_path); then
        log_debug "Softaculous is niet aanwezig, automatische upgrades worden niet ingesteld"
        return 0
    fi
    if [ "$apply" != "1" ]; then
        record_finding \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=softaculous-auto-upgrade" \
            "title=Automatische WordPress-upgrades in Softaculous staan niet aan" \
            "detail=Met automatische upgrades landen toekomstige beveiligingsreleases vanzelf op alle beheerde installaties." \
            "remediation=Draai harden met --apply." \
            "action=proposed"
        return 0
    fi
    log_info "Automatische upgrades inschakelen in Softaculous"
    if php -d open_basedir= -d disable_functions= "$cli" \
        --enable-auto-upgrade --core --plugins --themes >/dev/null 2>&1; then
        audit_write "harden softaculous auto-upgrade=enabled"
        record_finding \
            "severity=$SEVERITY_INFO" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=softaculous-auto-upgrade" \
            "title=Automatische upgrades in Softaculous staan aan" \
            "detail=Bestaande installaties werken zichzelf voortaan bij." \
            "remediation=Voor toekomstige nieuwe installaties moet daarnaast force_auto_upgrade ingesteld worden in universal.custom.php, dat is een handmatige stap." \
            "action=applied"
        return 0
    fi
    log_warn "Kon automatische upgrades in Softaculous niet inschakelen"
    record_finding \
        "severity=$SEVERITY_MEDIUM" \
        "confidence=$CONFIDENCE_HEURISTIC" \
        "category=softaculous-auto-upgrade" \
        "title=Automatische upgrades in Softaculous konden niet ingesteld worden" \
        "detail=De aanroep van de Softaculous CLI is mislukt." \
        "remediation=Zet automatische upgrades handmatig aan in het Softaculous-beheerscherm."
    return 1
}

remove_stopgap_muplugin() {
    local site_path=$1 apply=$2 patched=$3
    local stopgap="$site_path/wp-content/mu-plugins/wp2shell-stopgap.php"
    if [ ! -f "$stopgap" ]; then
        return 0
    fi
    if [ "$patched" != "1" ]; then
        log_info "De tijdelijke mu-plugin blijft staan want deze site is nog niet gepatcht"
        return 0
    fi
    if [ "$apply" != "1" ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_LOW" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=stopgap-removable" \
            "title=De tijdelijke mu-plugin kan weg" \
            "detail=Deze site is gepatcht, dus de tijdelijke noodmaatregel is niet meer nodig." \
            "file=$stopgap" \
            "remediation=Draai harden met --apply." \
            "action=proposed"
        return 0
    fi
    if quarantine_file "$site_path" "$stopgap" "tijdelijke mu-plugin niet meer nodig na patchen" "$CONFIDENCE_HIGH"; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_INFO" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=stopgap-removed" \
            "title=De tijdelijke mu-plugin is opgeruimd" \
            "detail=Het bestand is naar quarantaine verplaatst en blijft daar herstelbaar." \
            "file=$stopgap" \
            "action=quarantined"
    fi
    return 0
}
