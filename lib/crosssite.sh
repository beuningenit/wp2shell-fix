WP2SHELL_CROSSSITE_LOADED=1

WP2SHELL_CROSSSITE_MIN_OWNERS=3
WP2SHELL_CROSSSITE_MIN_OWNERS_CONFIRMED=2
WP2SHELL_CROSSSITE_SEVERE_OWNERS=5
WP2SHELL_CROSSSITE_SEVERE_OWNERS_CONFIRMED=3
WP2SHELL_CROSSSITE_MAX_EXAMPLE_SITES=8
WP2SHELL_CROSSSITE_MAX_REPORTED_HASHES=50
WP2SHELL_CROSSSITE_TRACK_LIMIT=2000
WP2SHELL_CROSSSITE_DISPLAY_MAX_CHARS=160
WP2SHELL_CROSSSITE_SIGNATURE_MAX_CHARS=200
WP2SHELL_CROSSSITE_EMPTY_FILE_SHA256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

WP2SHELL_CROSSSITE_STATE_DIR=""
WP2SHELL_CROSSSITE_UID=""
WP2SHELL_CROSSSITE_OWNER_CACHE_SITE=""
WP2SHELL_CROSSSITE_OWNER_CACHE_VALUE=""
WP2SHELL_CROSSSITE_REPORTED=0
WP2SHELL_CROSSSITE_SUPPRESSED=0

WP2SHELL_CROSSSITE_IGNORE_RELATIVE_GLOBS=(
    "wp-content/mu-plugins/wp2shell-*.php"
    "wp-content/mu-plugins/wp2shell-*/*"
    "wp-content/languages/*"
)

WP2SHELL_CROSSSITE_VENDOR_GLOBS=(
    "*/vendor/*"
    "*/vendor_prefixed/*"
    "*/node_modules/*"
    "*/composer/*"
    "*/phpmailer/*"
    "*/PHPMailer/*"
    "*/getid3/*"
    "*/tcpdf/*"
    "*/fpdf/*"
    "*/dompdf/*"
    "*/mpdf/*"
    "*/simplepie/*"
    "*/SimplePie/*"
    "*/guzzlehttp/*"
    "*/psr/*"
    "*/twig/*"
    "*/symfony/*"
    "*/monolog/*"
    "*/requests/*"
    "*/Requests/*"
)

crosssite_sanitize_owner() {
    local raw=$1 cleaned
    cleaned=${raw//[^A-Za-z0-9._-]/_}
    if [ -z "$cleaned" ]; then
        printf '%s' '-'
        return 1
    fi
    printf '%s' "$cleaned"
    return 0
}

crosssite_sanitize_signature() {
    local raw=$1 cleaned
    cleaned=${raw//[^A-Za-z0-9._\/-]/_}
    if [ -z "$cleaned" ]; then
        cleaned='-'
    fi
    if [ "${#cleaned}" -gt "${WP2SHELL_CROSSSITE_SIGNATURE_MAX_CHARS:-200}" ]; then
        cleaned=${cleaned:0:${WP2SHELL_CROSSSITE_SIGNATURE_MAX_CHARS:-200}}
    fi
    printf '%s' "$cleaned"
    return 0
}

crosssite_display_path() {
    local raw=$1
    local limit=${WP2SHELL_CROSSSITE_DISPLAY_MAX_CHARS:-160}
    raw=$(sanitize_text "$raw")
    raw=${raw//$'\n'/ }
    raw=${raw//$'\r'/ }
    raw=${raw//$'\t'/ }
    if [ -z "$raw" ]; then
        raw='onleesbaar pad'
    fi
    if [ "${#raw}" -gt "$limit" ]; then
        raw="${raw:0:$limit}..."
    fi
    printf '%s' "$raw"
    return 0
}

crosssite_encode() {
    path_to_base64 "$1"
    return 0
}

crosssite_decode() {
    local encoded=$1 decoded
    decoded=$(printf '%s' "$encoded" | base64 -d 2>/dev/null) || decoded=''
    printf '%s' "$decoded"
    return 0
}

crosssite_current_uid() {
    if [ -n "$WP2SHELL_CROSSSITE_UID" ]; then
        printf '%s' "$WP2SHELL_CROSSSITE_UID"
        return 0
    fi
    local value
    value=$(id -u 2>/dev/null) || value=''
    if [ -z "$value" ]; then
        return 1
    fi
    WP2SHELL_CROSSSITE_UID="$value"
    printf '%s' "$value"
    return 0
}

crosssite_state_directory() {
    if [ -n "$WP2SHELL_CROSSSITE_STATE_DIR" ] && [ -d "$WP2SHELL_CROSSSITE_STATE_DIR" ]; then
        printf '%s' "$WP2SHELL_CROSSSITE_STATE_DIR"
        return 0
    fi
    local base=${TMPDIR:-/tmp}
    base=${base%/}
    if [ -z "$base" ] || [ ! -d "$base" ]; then
        base=/tmp
    fi
    local key="${WP2SHELL_RUN_ID:-losse-run}-$$"
    key=${key//[^A-Za-z0-9._-]/_}
    local dir="$base/wp2shell-crosssite-$key"
    if [ -L "$dir" ]; then
        log_error "Het pad voor de kruisvergelijking is een symlink en wordt niet gebruikt: $dir"
        return 1
    fi
    if [ ! -d "$dir" ]; then
        mkdir -m 0700 -- "$dir" 2>/dev/null || true
    fi
    if [ -L "$dir" ] || [ ! -d "$dir" ]; then
        log_error "Kan de werkmap voor de kruisvergelijking niet aanmaken: $dir"
        return 1
    fi
    local uid dir_uid dir_mode
    if ! uid=$(crosssite_current_uid); then
        log_error "Kan het eigen gebruikersnummer niet bepalen, de kruisvergelijking wordt niet gestart"
        return 1
    fi
    dir_uid=$(stat -c '%u' -- "$dir" 2>/dev/null) || dir_uid=''
    dir_mode=$(stat -c '%a' -- "$dir" 2>/dev/null) || dir_mode=''
    if [ "$dir_uid" != "$uid" ] || [ "$dir_mode" != "700" ]; then
        log_error "De werkmap voor de kruisvergelijking heeft een verkeerde eigenaar of verkeerde rechten: $dir"
        return 1
    fi
    WP2SHELL_CROSSSITE_STATE_DIR="$dir"
    register_temp_cleanup "$dir"
    printf '%s' "$dir"
    return 0
}

crosssite_state_file() {
    local dir
    if ! dir=$(crosssite_state_directory); then
        return 1
    fi
    printf '%s/candidates' "$dir"
    return 0
}

crosssite_mark_degraded() {
    local dir
    if ! dir=$(crosssite_state_directory); then
        log_error "De kruisvergelijking mist gegevens en dat kon niet vastgelegd worden"
        return 1
    fi
    printf '%s\n' "$(timestamp_iso)" >> "$dir/degraded" 2>/dev/null || true
    return 0
}

crosssite_discard_state() {
    if [ -z "$WP2SHELL_CROSSSITE_STATE_DIR" ]; then
        return 0
    fi
    case $WP2SHELL_CROSSSITE_STATE_DIR in
        /tmp/wp2shell-crosssite-*|/var/tmp/wp2shell-crosssite-*)
            rm -rf -- "$WP2SHELL_CROSSSITE_STATE_DIR" 2>/dev/null || true
            ;;
        */wp2shell-crosssite-*)
            rm -rf -- "$WP2SHELL_CROSSSITE_STATE_DIR" 2>/dev/null || true
            ;;
    esac
    WP2SHELL_CROSSSITE_STATE_DIR=""
    return 0
}

crosssite_owner_for_site() {
    local site_path=$1 owner=''
    if [ "$WP2SHELL_CROSSSITE_OWNER_CACHE_SITE" = "$site_path" ] && [ -n "$WP2SHELL_CROSSSITE_OWNER_CACHE_VALUE" ]; then
        printf '%s' "$WP2SHELL_CROSSSITE_OWNER_CACHE_VALUE"
        return 0
    fi
    if declare -F directadmin_user_from_path >/dev/null 2>&1; then
        owner=$(directadmin_user_from_path "$site_path") || owner=''
    fi
    if [ -z "$owner" ]; then
        owner=$(path_owner "$site_path") || owner=''
    fi
    if [ -z "$owner" ]; then
        return 1
    fi
    if ! owner=$(crosssite_sanitize_owner "$owner"); then
        return 1
    fi
    WP2SHELL_CROSSSITE_OWNER_CACHE_SITE="$site_path"
    WP2SHELL_CROSSSITE_OWNER_CACHE_VALUE="$owner"
    printf '%s' "$owner"
    return 0
}

crosssite_relative_path() {
    local site_path=$1 file_path=$2
    case $file_path in
        "$site_path"/*)
            printf '%s' "${file_path#"$site_path"/}"
            return 0
            ;;
    esac
    printf '%s' "$file_path"
    return 1
}

crosssite_package_signature() {
    local relative=$1 remainder='' package=''
    case $relative in
        wp-content/plugins/*/*)
            remainder=${relative#wp-content/plugins/}
            package="plugins/${remainder%%/*}"
            ;;
        wp-content/themes/*/*)
            remainder=${relative#wp-content/themes/}
            package="themes/${remainder%%/*}"
            ;;
        wp-content/mu-plugins/*/*)
            remainder=${relative#wp-content/mu-plugins/}
            package="mu-plugins/${remainder%%/*}"
            ;;
        *) return 1 ;;
    esac
    printf '%s/%s' "$package" "${relative##*/}"
    return 0
}

crosssite_signature_token() {
    local relative=$1 signature=''
    if signature=$(crosssite_package_signature "$relative"); then
        printf 'pkg:%s' "$(crosssite_sanitize_signature "$signature")"
        return 0
    fi
    printf 'los:%s' "$(crosssite_sanitize_signature "$relative")"
    return 0
}

crosssite_path_is_vendor() {
    local relative=$1 glob
    local probe="/$relative"
    for glob in "${WP2SHELL_CROSSSITE_VENDOR_GLOBS[@]+"${WP2SHELL_CROSSSITE_VENDOR_GLOBS[@]}"}"; do
        if [ -z "$glob" ]; then
            continue
        fi
        case $probe in
            $glob) return 0 ;;
        esac
    done
    return 1
}

crosssite_relative_is_ignored() {
    local relative=$1 glob
    for glob in "${WP2SHELL_CROSSSITE_IGNORE_RELATIVE_GLOBS[@]+"${WP2SHELL_CROSSSITE_IGNORE_RELATIVE_GLOBS[@]}"}"; do
        if [ -z "$glob" ]; then
            continue
        fi
        case $relative in
            $glob) return 0 ;;
        esac
    done
    return 1
}

crosssite_hash_is_usable() {
    local candidate=$1
    if [ "${#candidate}" -ne 64 ]; then
        return 1
    fi
    case $candidate in
        *[!0-9a-f]*) return 1 ;;
    esac
    return 0
}

crosssite_record_candidate() {
    local site_path=${1:-}
    local file_path=${2:-}
    local sha256=${3:-}
    local origin=${4:-$CONFIDENCE_HEURISTIC}
    if [ -z "$site_path" ] || [ -z "$file_path" ]; then
        log_warn "crosssite_record_candidate zonder sitepad of bestandspad aangeroepen, de kruisvergelijking mist dit bestand"
        crosssite_mark_degraded
        return 1
    fi
    site_path=${site_path%/}
    sha256=${sha256,,}
    if ! crosssite_hash_is_usable "$sha256"; then
        log_warn "Geen bruikbare sha256 voor $file_path, dit bestand doet niet mee aan de kruisvergelijking"
        crosssite_mark_degraded
        return 1
    fi
    if [ "$sha256" = "${WP2SHELL_CROSSSITE_EMPTY_FILE_SHA256:-}" ]; then
        log_debug "Leeg bestand telt niet mee in de kruisvergelijking: $file_path"
        return 0
    fi
    local relative
    relative=$(crosssite_relative_path "$site_path" "$file_path") || \
        log_debug "Bestand ligt buiten het sitepad, het volledige pad wordt gebruikt: $file_path"
    if is_allowlisted_path "$file_path"; then
        log_debug "Op de allowlist, telt niet mee in de kruisvergelijking: $file_path"
        return 0
    fi
    if crosssite_relative_is_ignored "$relative"; then
        log_debug "Uitgesloten pad voor de kruisvergelijking: $relative"
        return 0
    fi
    local owner
    if ! owner=$(crosssite_owner_for_site "$site_path"); then
        log_warn "Kan de eigenaar van $site_path niet bepalen, dit bestand doet niet mee aan de kruisvergelijking"
        crosssite_mark_degraded
        return 1
    fi
    local flag='heuristiek'
    case $origin in
        "$CONFIDENCE_HIGH"|confirmed|bevestigd) flag='bevestigd' ;;
    esac
    local vendor='geen'
    if crosssite_path_is_vendor "$relative"; then
        vendor='vendor'
    fi
    local signature
    signature=$(crosssite_signature_token "$relative")
    local state_file
    if ! state_file=$(crosssite_state_file); then
        log_error "Kan de kandidaat voor de kruisvergelijking niet opslaan: $file_path"
        return 1
    fi
    local site_encoded file_encoded
    site_encoded=$(crosssite_encode "$site_path")
    file_encoded=$(crosssite_encode "$file_path")
    if [ -z "$site_encoded" ] || [ -z "$file_encoded" ]; then
        log_warn "Kan de paden voor de kruisvergelijking niet coderen: $file_path"
        crosssite_mark_degraded
        return 1
    fi
    if ! printf '%s %s %s %s %s %s %s\n' \
        "$sha256" "$owner" "$site_encoded" "$file_encoded" "$signature" "$vendor" "$flag" \
        >> "$state_file"; then
        log_error "Kan niet naar het werkbestand van de kruisvergelijking schrijven: $state_file"
        crosssite_mark_degraded
        return 1
    fi
    return 0
}

crosssite_group_reset() {
    WP2SHELL_CROSSSITE_GROUP_HASH=""
    WP2SHELL_CROSSSITE_GROUP_OWNERS=" "
    WP2SHELL_CROSSSITE_GROUP_OWNER_COUNT=0
    WP2SHELL_CROSSSITE_GROUP_SITES=" "
    WP2SHELL_CROSSSITE_GROUP_SITE_COUNT=0
    WP2SHELL_CROSSSITE_GROUP_SIGNATURES=" "
    WP2SHELL_CROSSSITE_GROUP_SIGNATURE_COUNT=0
    WP2SHELL_CROSSSITE_GROUP_OCCURRENCES=0
    WP2SHELL_CROSSSITE_GROUP_CONFIRMED=0
    WP2SHELL_CROSSSITE_GROUP_VENDOR=0
    WP2SHELL_CROSSSITE_GROUP_PACKAGE_ONLY=1
    WP2SHELL_CROSSSITE_GROUP_TRUNCATED=0
    WP2SHELL_CROSSSITE_GROUP_EXAMPLES=""
    WP2SHELL_CROSSSITE_GROUP_EXAMPLE_COUNT=0
    return 0
}

crosssite_set_contains() {
    local haystack=$1 token=$2
    case $haystack in
        *" $token "*) return 0 ;;
    esac
    return 1
}

crosssite_group_add() {
    local owner=$1 site_encoded=$2 file_encoded=$3 signature=$4 vendor=$5 flag=$6
    local limit=${WP2SHELL_CROSSSITE_TRACK_LIMIT:-2000}
    WP2SHELL_CROSSSITE_GROUP_OCCURRENCES=$((WP2SHELL_CROSSSITE_GROUP_OCCURRENCES + 1))
    if [ "$flag" = "bevestigd" ]; then
        WP2SHELL_CROSSSITE_GROUP_CONFIRMED=1
    fi
    if [ "$vendor" = "vendor" ]; then
        WP2SHELL_CROSSSITE_GROUP_VENDOR=1
    fi
    case $signature in
        pkg:*) ;;
        *) WP2SHELL_CROSSSITE_GROUP_PACKAGE_ONLY=0 ;;
    esac
    if ! crosssite_set_contains "$WP2SHELL_CROSSSITE_GROUP_OWNERS" "$owner"; then
        if [ "$WP2SHELL_CROSSSITE_GROUP_OWNER_COUNT" -lt "$limit" ]; then
            WP2SHELL_CROSSSITE_GROUP_OWNERS="$WP2SHELL_CROSSSITE_GROUP_OWNERS$owner "
            WP2SHELL_CROSSSITE_GROUP_OWNER_COUNT=$((WP2SHELL_CROSSSITE_GROUP_OWNER_COUNT + 1))
        else
            WP2SHELL_CROSSSITE_GROUP_TRUNCATED=1
        fi
    fi
    if ! crosssite_set_contains "$WP2SHELL_CROSSSITE_GROUP_SIGNATURES" "$signature"; then
        if [ "$WP2SHELL_CROSSSITE_GROUP_SIGNATURE_COUNT" -lt "$limit" ]; then
            WP2SHELL_CROSSSITE_GROUP_SIGNATURES="$WP2SHELL_CROSSSITE_GROUP_SIGNATURES$signature "
            WP2SHELL_CROSSSITE_GROUP_SIGNATURE_COUNT=$((WP2SHELL_CROSSSITE_GROUP_SIGNATURE_COUNT + 1))
        else
            WP2SHELL_CROSSSITE_GROUP_TRUNCATED=1
        fi
    fi
    if crosssite_set_contains "$WP2SHELL_CROSSSITE_GROUP_SITES" "$site_encoded"; then
        return 0
    fi
    if [ "$WP2SHELL_CROSSSITE_GROUP_SITE_COUNT" -lt "$limit" ]; then
        WP2SHELL_CROSSSITE_GROUP_SITES="$WP2SHELL_CROSSSITE_GROUP_SITES$site_encoded "
        WP2SHELL_CROSSSITE_GROUP_SITE_COUNT=$((WP2SHELL_CROSSSITE_GROUP_SITE_COUNT + 1))
    else
        WP2SHELL_CROSSSITE_GROUP_TRUNCATED=1
        return 0
    fi
    local maximum=${WP2SHELL_CROSSSITE_MAX_EXAMPLE_SITES:-8}
    if [ "$WP2SHELL_CROSSSITE_GROUP_EXAMPLE_COUNT" -ge "$maximum" ]; then
        return 0
    fi
    local decoded shown
    decoded=$(crosssite_decode "$file_encoded")
    shown=$(crosssite_display_path "$decoded")
    if [ -n "$WP2SHELL_CROSSSITE_GROUP_EXAMPLES" ]; then
        WP2SHELL_CROSSSITE_GROUP_EXAMPLES="$WP2SHELL_CROSSSITE_GROUP_EXAMPLES; "
    fi
    WP2SHELL_CROSSSITE_GROUP_EXAMPLES="$WP2SHELL_CROSSSITE_GROUP_EXAMPLES$owner: $shown"
    WP2SHELL_CROSSSITE_GROUP_EXAMPLE_COUNT=$((WP2SHELL_CROSSSITE_GROUP_EXAMPLE_COUNT + 1))
    return 0
}

crosssite_group_owner_list() {
    local raw=${WP2SHELL_CROSSSITE_GROUP_OWNERS# }
    raw=${raw% }
    printf '%s' "${raw// /, }"
    return 0
}

crosssite_group_should_skip() {
    local minimum=${WP2SHELL_CROSSSITE_MIN_OWNERS:-3}
    if [ "$WP2SHELL_CROSSSITE_GROUP_CONFIRMED" = "1" ]; then
        minimum=${WP2SHELL_CROSSSITE_MIN_OWNERS_CONFIRMED:-2}
    fi
    if [ "$minimum" -lt 2 ]; then
        minimum=2
    fi
    if [ "$WP2SHELL_CROSSSITE_GROUP_OWNER_COUNT" -lt "$minimum" ]; then
        return 0
    fi
    if [ "$WP2SHELL_CROSSSITE_GROUP_CONFIRMED" = "1" ]; then
        return 1
    fi
    if [ "$WP2SHELL_CROSSSITE_GROUP_VENDOR" = "1" ]; then
        log_debug "Kruisvergelijking slaat $WP2SHELL_CROSSSITE_GROUP_HASH over, het bestand staat in een vendor-map"
        return 0
    fi
    if [ "$WP2SHELL_CROSSSITE_GROUP_PACKAGE_ONLY" = "1" ] && [ "$WP2SHELL_CROSSSITE_GROUP_SIGNATURE_COUNT" -le 1 ]; then
        log_debug "Kruisvergelijking slaat $WP2SHELL_CROSSSITE_GROUP_HASH over, dit is een gedeelde plugin of thema op hetzelfde pad"
        return 0
    fi
    return 1
}

crosssite_group_severity() {
    if [ "$WP2SHELL_CROSSSITE_GROUP_CONFIRMED" = "1" ]; then
        if [ "$WP2SHELL_CROSSSITE_GROUP_OWNER_COUNT" -ge "${WP2SHELL_CROSSSITE_SEVERE_OWNERS_CONFIRMED:-3}" ]; then
            printf '%s' "$SEVERITY_CRITICAL"
        else
            printf '%s' "$SEVERITY_HIGH"
        fi
        return 0
    fi
    if [ "$WP2SHELL_CROSSSITE_GROUP_OWNER_COUNT" -ge "${WP2SHELL_CROSSSITE_SEVERE_OWNERS:-5}" ]; then
        printf '%s' "$SEVERITY_HIGH"
    else
        printf '%s' "$SEVERITY_MEDIUM"
    fi
    return 0
}

crosssite_group_emit() {
    local severity confidence category title owner_list count_prefix=''
    severity=$(crosssite_group_severity)
    if [ "$WP2SHELL_CROSSSITE_GROUP_TRUNCATED" = "1" ]; then
        count_prefix='minstens '
    fi
    owner_list=$(crosssite_group_owner_list)
    local examples="$WP2SHELL_CROSSSITE_GROUP_EXAMPLES"
    local hidden=$((WP2SHELL_CROSSSITE_GROUP_SITE_COUNT - WP2SHELL_CROSSSITE_GROUP_EXAMPLE_COUNT))
    if [ "$hidden" -gt 0 ]; then
        examples="$examples en nog $hidden andere site(s)"
    fi
    local shared_note
    shared_note="Gedeelde pakketten zijn hier al uitgefilterd: een bestand dat bij elk voorkomen op precies hetzelfde pad binnen dezelfde plugin- of themamap staat is overgeslagen, net als alles in een vendor-map, want een premium plugin of een gedeelde bibliotheek staat per definitie op elke site met dezelfde hash."
    local scope_note
    scope_note="Alleen bestanden die op hun eigen site al als verdacht waren aangemerkt komen in deze vergelijking terecht. Zonder dat filter zou de hele WordPress-core op elke site met zichzelf overeenkomen en zegt een treffer niets."
    local quarantine_note
    quarantine_note="Deze categorie wordt nooit automatisch in quarantaine gezet, ook niet met clean --apply."
    if [ "$WP2SHELL_CROSSSITE_GROUP_CONFIRMED" = "1" ]; then
        confidence="$CONFIDENCE_HIGH"
        category="cross-site-confirmed-hash"
        title="Bevestigd kwaadaardig bestand staat bij $count_prefix$WP2SHELL_CROSSSITE_GROUP_OWNER_COUNT klanten"
        record_finding \
            "severity=$severity" \
            "confidence=$confidence" \
            "category=$category" \
            "title=$title" \
            "detail=Dit bestand is op minstens een site als bevestigd kwaadaardig aangemerkt en exact dezelfde sha256 staat ook op sites van andere systeemgebruikers: $owner_list. Bij elkaar $WP2SHELL_CROSSSITE_GROUP_OCCURRENCES voorkomen(s) op $count_prefix$WP2SHELL_CROSSSITE_GROUP_SITE_COUNT site(s) en $WP2SHELL_CROSSSITE_GROUP_SIGNATURE_COUNT verschillend(e) pad(en). $scope_note De toegevoegde waarde boven de losse bevindingen zit in de accountgrens: de losse bevinding zegt dat een site besmet is, deze bevinding zegt dat hetzelfde artefact over meerdere klantaccounts heen staat en dat de besmetting zich dus over de server verplaatst heeft in plaats van via een enkele kwetsbare site binnen te zijn gekomen. Voorbeeldpaden: $examples. $quarantine_note" \
            "evidence=sha256 $WP2SHELL_CROSSSITE_GROUP_HASH, $count_prefix$WP2SHELL_CROSSSITE_GROUP_OWNER_COUNT eigenaren, $count_prefix$WP2SHELL_CROSSSITE_GROUP_SITE_COUNT sites" \
            "remediation=Behandel elk van deze sites als gecompromitteerd, zet de genoemde bestanden na een backup in quarantaine, en zoek naar de gedeelde toegangsweg tussen de accounts, bijvoorbeeld een schrijfbare gedeelde map, een gedeelde FTP-account of een lek in een beheerpaneel."
        return 0
    fi
    confidence="$CONFIDENCE_HEURISTIC"
    category="cross-site-identical-file"
    title="Zelfde verdachte bestand bij $count_prefix$WP2SHELL_CROSSSITE_GROUP_OWNER_COUNT verschillende klanten"
    record_finding \
        "severity=$severity" \
        "confidence=$confidence" \
        "category=$category" \
        "title=$title" \
        "detail=Een bestand met sha256 $WP2SHELL_CROSSSITE_GROUP_HASH komt byte voor byte terug op sites van $count_prefix$WP2SHELL_CROSSSITE_GROUP_OWNER_COUNT verschillende systeemgebruikers: $owner_list. Bij elkaar $WP2SHELL_CROSSSITE_GROUP_OCCURRENCES voorkomen(s) op $count_prefix$WP2SHELL_CROSSSITE_GROUP_SITE_COUNT site(s) en $WP2SHELL_CROSSSITE_GROUP_SIGNATURE_COUNT verschillend(e) pad(en). $scope_note $shared_note Wat dan overblijft is precies wat de losse bevindingen niet kunnen zeggen: die melden per site een twijfelgeval, terwijl identieke inhoud onder klanten die administratief niets met elkaar te maken hebben niet door toeval of door een gedeelde pluginversie te verklaren is. Er is per site vergeleken op hash en niet op pad, want een dropper krijgt op elke site een andere naam. Voorbeeldpaden: $examples. Dit blijft een heuristiek: bekijk de inhoud van deze bestanden handmatig voordat er iets verplaatst wordt. $quarantine_note" \
        "evidence=sha256 $WP2SHELL_CROSSSITE_GROUP_HASH, $count_prefix$WP2SHELL_CROSSSITE_GROUP_OWNER_COUNT eigenaren, $count_prefix$WP2SHELL_CROSSSITE_GROUP_SITE_COUNT sites" \
        "remediation=Bekijk een van de genoemde bestanden handmatig. Blijkt het kwaadaardig, behandel dan alle genoemde sites als besmet en zoek de gedeelde toegangsweg tussen deze accounts. Blijkt het legitiem, zet het pad dan in WP2SHELL_ALLOWLIST_PATHS."
    return 0
}

crosssite_group_flush() {
    if [ -z "$WP2SHELL_CROSSSITE_GROUP_HASH" ]; then
        return 0
    fi
    if crosssite_group_should_skip; then
        return 0
    fi
    local maximum=${WP2SHELL_CROSSSITE_MAX_REPORTED_HASHES:-50}
    if [ "$WP2SHELL_CROSSSITE_REPORTED" -ge "$maximum" ]; then
        WP2SHELL_CROSSSITE_SUPPRESSED=$((WP2SHELL_CROSSSITE_SUPPRESSED + 1))
        return 0
    fi
    crosssite_group_emit
    WP2SHELL_CROSSSITE_REPORTED=$((WP2SHELL_CROSSSITE_REPORTED + 1))
    return 0
}

crosssite_report_unavailable() {
    local reason=$1
    record_finding \
        "severity=$SEVERITY_MEDIUM" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=cross-site-correlation-unavailable" \
        "title=De kruisvergelijking tussen sites is niet uitgevoerd" \
        "detail=De vergelijking van verdachte bestanden tussen de sites op deze server kon niet draaien. Reden: $reason. Malware die op meerdere klantaccounts tegelijk staat wordt daardoor in deze run niet als zodanig herkend. Het uitblijven van kruisverbanden in dit rapport betekent hier dus niet dat ze er niet zijn." \
        "remediation=Controleer de schrijfrechten op de tijdelijke map en draai de scan opnieuw."
    return 0
}

crosssite_report_degraded() {
    record_finding \
        "severity=$SEVERITY_MEDIUM" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=cross-site-correlation-incomplete" \
        "title=De kruisvergelijking tussen sites is onvolledig" \
        "detail=Een deel van de verdachte bestanden kon niet aan de kruisvergelijking meedoen, bijvoorbeeld omdat er geen sha256 berekend kon worden of omdat de eigenaar van een installatie niet vast te stellen was. De vergelijking heeft wel gedraaid, maar over een onvolledige verzameling. Een uitkomst zonder kruisverbanden mag daarom niet als bewijs gelezen worden dat malware zich niet over meerdere klanten verspreid heeft." \
        "remediation=Bekijk het runlogboek op de regels over de kruisvergelijking en draai de scan opnieuw als root."
    return 0
}

crosssite_report_suppressed() {
    record_finding \
        "severity=$SEVERITY_MEDIUM" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=cross-site-correlation-truncated" \
        "title=$WP2SHELL_CROSSSITE_SUPPRESSED kruisverbanden zijn niet apart gerapporteerd" \
        "detail=Er zijn meer bestanden gevonden die bij verschillende klanten identiek terugkomen dan er los gemeld worden. Boven de grens van ${WP2SHELL_CROSSSITE_MAX_REPORTED_HASHES:-50} bevindingen is de rest geteld en niet uitgeschreven, zodat het rapport leesbaar blijft. Deze $WP2SHELL_CROSSSITE_SUPPRESSED gevallen zijn dus wel gevonden en niet weggevallen." \
        "remediation=Behandel dit als een serverbreed incident en verhoog WP2SHELL_CROSSSITE_MAX_REPORTED_HASHES als u de volledige lijst nodig heeft."
    return 0
}

crosssite_report() {
    WP2SHELL_CROSSSITE_REPORTED=0
    WP2SHELL_CROSSSITE_SUPPRESSED=0
    local dir
    if ! dir=$(crosssite_state_directory); then
        crosssite_report_unavailable "de werkmap voor de vergelijking kon niet veilig aangemaakt worden"
        return 0
    fi
    local degraded=0
    if [ -e "$dir/degraded" ]; then
        degraded=1
    fi
    local state="$dir/candidates"
    if [ ! -s "$state" ]; then
        log_debug "Geen kandidaten voor de kruisvergelijking"
        if [ "$degraded" = "1" ]; then
            crosssite_report_degraded
        fi
        crosssite_discard_state
        return 0
    fi
    local sorted status=0
    sorted=$(mktemp -t wp2shell-crosssite-sorted.XXXXXXXX) || {
        crosssite_report_unavailable "er kon geen tijdelijk bestand aangemaakt worden om de kandidaten te sorteren"
        crosssite_discard_state
        return 0
    }
    register_temp_cleanup "$sorted"
    LC_ALL=C "${WP2SHELL_SORT:-sort}" -u -- "$state" > "$sorted" 2>/dev/null || status=$?
    if [ "$status" -ne 0 ] || [ ! -s "$sorted" ]; then
        crosssite_report_unavailable "het sorteren van de kandidaten gaf exitcode $status"
        rm -f -- "$sorted"
        crosssite_discard_state
        return 0
    fi
    crosssite_group_reset
    local hash owner site_encoded file_encoded signature vendor flag
    while IFS=' ' read -r hash owner site_encoded file_encoded signature vendor flag || [ -n "$hash" ]; do
        if [ -z "$hash" ] || [ -z "$owner" ] || [ -z "$site_encoded" ] || [ -z "$file_encoded" ]; then
            continue
        fi
        if [ "$hash" != "$WP2SHELL_CROSSSITE_GROUP_HASH" ]; then
            crosssite_group_flush
            crosssite_group_reset
            WP2SHELL_CROSSSITE_GROUP_HASH="$hash"
        fi
        crosssite_group_add "$owner" "$site_encoded" "$file_encoded" "$signature" "$vendor" "$flag"
    done < "$sorted"
    crosssite_group_flush
    crosssite_group_reset
    rm -f -- "$sorted"
    if [ "$WP2SHELL_CROSSSITE_SUPPRESSED" -gt 0 ]; then
        crosssite_report_suppressed
    fi
    if [ "$degraded" = "1" ]; then
        crosssite_report_degraded
    fi
    log_info "Kruisvergelijking klaar, $WP2SHELL_CROSSSITE_REPORTED kruisverband(en) gemeld"
    crosssite_discard_state
    return 0
}
