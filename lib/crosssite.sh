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
        return 1
    fi
    printf '%s' "$cleaned"
    return 0
}

crosssite_sanitize_signature() {
    local raw=$1 cleaned limit
    limit=${WP2SHELL_CROSSSITE_SIGNATURE_MAX_CHARS:-200}
    cleaned=${raw//[^A-Za-z0-9._\/-]/_}
    if [ -z "$cleaned" ]; then
        cleaned='-'
    fi
    if [ "${#cleaned}" -gt "$limit" ]; then
        cleaned=${cleaned:0:$limit}
    fi
    printf '%s' "$cleaned"
    return 0
}

crosssite_display_path() {
    local raw=$1 limit head_size tail_size
    limit=${WP2SHELL_CROSSSITE_DISPLAY_MAX_CHARS:-160}
    raw=$(sanitize_text "$raw")
    raw=${raw//$'\n'/ }
    raw=${raw//$'\r'/ }
    raw=${raw//$'\t'/ }
    if [ -z "$raw" ]; then
        raw='pad onleesbaar'
    fi
    if [ "$limit" -lt 40 ]; then
        limit=40
    fi
    if [ "${#raw}" -gt "$limit" ]; then
        head_size=$((limit / 3))
        tail_size=$((limit - head_size - 3))
        raw="${raw:0:$head_size}...${raw: -$tail_size}"
    fi
    printf '%s' "$raw"
    return 0
}

crosssite_decode_path() {
    local encoded=$1 decoded
    decoded=$(printf '%s' "$encoded" | base64 -d 2>/dev/null) || decoded=''
    printf '%s' "$decoded"
    return 0
}

crosssite_ensure_uid() {
    if [ -n "$WP2SHELL_CROSSSITE_UID" ]; then
        return 0
    fi
    local value
    value=$(id -u 2>/dev/null) || value=''
    if [ -z "$value" ]; then
        return 1
    fi
    WP2SHELL_CROSSSITE_UID="$value"
    return 0
}

crosssite_ensure_state_directory() {
    if [ -n "$WP2SHELL_CROSSSITE_STATE_DIR" ] && [ ! -L "$WP2SHELL_CROSSSITE_STATE_DIR" ] &&
        [ -d "$WP2SHELL_CROSSSITE_STATE_DIR" ]; then
        return 0
    fi
    if ! crosssite_ensure_uid; then
        log_error "Kan het eigen gebruikersnummer niet bepalen, de kruisvergelijking tussen sites start niet"
        return 1
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
        log_error "Het werkpad van de kruisvergelijking is een symlink en wordt niet gebruikt: $dir"
        return 1
    fi
    if [ ! -d "$dir" ]; then
        mkdir -m 0700 -- "$dir" 2>/dev/null || true
    fi
    if [ -L "$dir" ] || [ ! -d "$dir" ]; then
        log_error "Kan de werkmap voor de kruisvergelijking niet aanmaken: $dir"
        return 1
    fi
    local dir_uid dir_mode
    dir_uid=$(stat -c '%u' -- "$dir" 2>/dev/null) || dir_uid=''
    dir_mode=$(stat -c '%a' -- "$dir" 2>/dev/null) || dir_mode=''
    if [ "$dir_uid" != "$WP2SHELL_CROSSSITE_UID" ] || [ "$dir_mode" != "700" ]; then
        log_error "De werkmap voor de kruisvergelijking heeft een andere eigenaar of ruimere rechten dan verwacht: $dir"
        return 1
    fi
    WP2SHELL_CROSSSITE_STATE_DIR="$dir"
    register_temp_cleanup "$dir"
    return 0
}

crosssite_state_directory() {
    if ! crosssite_ensure_state_directory; then
        return 1
    fi
    printf '%s' "$WP2SHELL_CROSSSITE_STATE_DIR"
    return 0
}

crosssite_mark_degraded() {
    if ! crosssite_ensure_state_directory; then
        log_error "De kruisvergelijking mist gegevens en dat kon nergens vastgelegd worden"
        return 1
    fi
    printf '%s\n' "$(timestamp_iso)" >> "$WP2SHELL_CROSSSITE_STATE_DIR/degraded" 2>/dev/null || true
    return 0
}

crosssite_discard_state() {
    if [ -z "$WP2SHELL_CROSSSITE_STATE_DIR" ]; then
        return 0
    fi
    case $WP2SHELL_CROSSSITE_STATE_DIR in
        */wp2shell-crosssite-*)
            if [ ! -L "$WP2SHELL_CROSSSITE_STATE_DIR" ] && [ -d "$WP2SHELL_CROSSSITE_STATE_DIR" ]; then
                rm -rf -- "$WP2SHELL_CROSSSITE_STATE_DIR" 2>/dev/null || true
            fi
            ;;
    esac
    WP2SHELL_CROSSSITE_STATE_DIR=""
    return 0
}

crosssite_resolve_owner() {
    local site_path=$1 owner=''
    if [ "$WP2SHELL_CROSSSITE_OWNER_CACHE_SITE" = "$site_path" ] &&
        [ -n "$WP2SHELL_CROSSSITE_OWNER_CACHE_VALUE" ]; then
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
        printf 'package:%s' "$(crosssite_sanitize_signature "$signature")"
        return 0
    fi
    printf 'loose:%s' "$(crosssite_sanitize_signature "$relative")"
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
    local origin=${4:-${CONFIDENCE_HEURISTIC:-heuristic}}
    if [ -z "$site_path" ] || [ -z "$file_path" ]; then
        log_warn "crosssite_record_candidate is zonder sitepad of bestandspad aangeroepen, dit bestand doet niet mee aan de kruisvergelijking"
        crosssite_mark_degraded
        return 1
    fi
    site_path=${site_path%/}
    sha256=${sha256,,}
    if ! crosssite_hash_is_usable "$sha256"; then
        log_warn "Geen bruikbare sha256 meegegeven voor $file_path, dit bestand doet niet mee aan de kruisvergelijking"
        crosssite_mark_degraded
        return 1
    fi
    if [ "$sha256" = "${WP2SHELL_CROSSSITE_EMPTY_FILE_SHA256:-}" ]; then
        log_debug "Leeg bestand telt niet mee in de kruisvergelijking: $file_path"
        return 0
    fi
    local relative
    relative=$(crosssite_relative_path "$site_path" "$file_path") ||
        log_debug "Bestand ligt buiten het sitepad, de kruisvergelijking gebruikt het volledige pad: $file_path"
    if is_allowlisted_path "$file_path"; then
        log_debug "Staat op de allowlist, telt niet mee in de kruisvergelijking: $file_path"
        return 0
    fi
    if crosssite_relative_is_ignored "$relative"; then
        log_debug "Uitgesloten pad voor de kruisvergelijking: $relative"
        return 0
    fi
    if ! crosssite_resolve_owner "$site_path"; then
        log_warn "Kan de eigenaar van $site_path niet vaststellen, dit bestand doet niet mee aan de kruisvergelijking"
        crosssite_mark_degraded
        return 1
    fi
    if ! crosssite_ensure_state_directory; then
        log_error "Kan deze kandidaat voor de kruisvergelijking niet opslaan: $file_path"
        return 1
    fi
    local flag='heuristic'
    case $origin in
        "${CONFIDENCE_HIGH:-high-confidence}"|confirmed) flag='confirmed' ;;
    esac
    local vendor='plain'
    if crosssite_path_is_vendor "$relative"; then
        vendor='vendor'
    fi
    local signature site_encoded file_encoded
    signature=$(crosssite_signature_token "$relative")
    site_encoded=$(path_to_base64 "$site_path")
    file_encoded=$(path_to_base64 "$file_path")
    if [ -z "$signature" ] || [ -z "$site_encoded" ] || [ -z "$file_encoded" ]; then
        log_warn "Kan de paden voor de kruisvergelijking niet coderen: $file_path"
        crosssite_mark_degraded
        return 1
    fi
    if ! printf '%s %s %s %s %s %s %s\n' \
        "$sha256" "$WP2SHELL_CROSSSITE_OWNER_CACHE_VALUE" "$site_encoded" "$file_encoded" \
        "$signature" "$vendor" "$flag" \
        >> "$WP2SHELL_CROSSSITE_STATE_DIR/candidates"; then
        log_error "Kan niet naar het werkbestand van de kruisvergelijking schrijven"
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

crosssite_group_add_example() {
    local owner=$1 file_encoded=$2
    local maximum=${WP2SHELL_CROSSSITE_MAX_EXAMPLE_SITES:-8}
    if [ "$WP2SHELL_CROSSSITE_GROUP_EXAMPLE_COUNT" -ge "$maximum" ]; then
        return 0
    fi
    local decoded shown
    decoded=$(crosssite_decode_path "$file_encoded")
    shown=$(crosssite_display_path "$decoded")
    if [ -n "$WP2SHELL_CROSSSITE_GROUP_EXAMPLES" ]; then
        WP2SHELL_CROSSSITE_GROUP_EXAMPLES="$WP2SHELL_CROSSSITE_GROUP_EXAMPLES; "
    fi
    WP2SHELL_CROSSSITE_GROUP_EXAMPLES="$WP2SHELL_CROSSSITE_GROUP_EXAMPLES$owner: $shown"
    WP2SHELL_CROSSSITE_GROUP_EXAMPLE_COUNT=$((WP2SHELL_CROSSSITE_GROUP_EXAMPLE_COUNT + 1))
    return 0
}

crosssite_group_add() {
    local owner=$1 site_encoded=$2 file_encoded=$3 signature=$4 vendor=$5 flag=$6
    local limit=${WP2SHELL_CROSSSITE_TRACK_LIMIT:-2000}
    WP2SHELL_CROSSSITE_GROUP_OCCURRENCES=$((WP2SHELL_CROSSSITE_GROUP_OCCURRENCES + 1))
    if [ "$flag" = "confirmed" ]; then
        WP2SHELL_CROSSSITE_GROUP_CONFIRMED=1
    fi
    if [ "$vendor" = "vendor" ]; then
        WP2SHELL_CROSSSITE_GROUP_VENDOR=1
    fi
    case $signature in
        package:*) ;;
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
    if [ "$WP2SHELL_CROSSSITE_GROUP_SITE_COUNT" -ge "$limit" ]; then
        WP2SHELL_CROSSSITE_GROUP_TRUNCATED=1
        return 0
    fi
    WP2SHELL_CROSSSITE_GROUP_SITES="$WP2SHELL_CROSSSITE_GROUP_SITES$site_encoded "
    WP2SHELL_CROSSSITE_GROUP_SITE_COUNT=$((WP2SHELL_CROSSSITE_GROUP_SITE_COUNT + 1))
    crosssite_group_add_example "$owner" "$file_encoded"
    return 0
}

crosssite_group_owner_list() {
    local raw=${WP2SHELL_CROSSSITE_GROUP_OWNERS# }
    raw=${raw% }
    printf '%s' "${raw// /, }"
    return 0
}

crosssite_group_example_list() {
    local examples=$WP2SHELL_CROSSSITE_GROUP_EXAMPLES
    local hidden=$((WP2SHELL_CROSSSITE_GROUP_SITE_COUNT - WP2SHELL_CROSSSITE_GROUP_EXAMPLE_COUNT))
    if [ -z "$examples" ]; then
        examples='geen leesbaar voorbeeldpad beschikbaar'
    fi
    if [ "$hidden" -gt 0 ]; then
        examples="$examples, en nog $hidden andere site(s)"
    fi
    printf '%s' "$examples"
    return 0
}

crosssite_group_should_skip() {
    local minimum=${WP2SHELL_CROSSSITE_MIN_OWNERS:-3}
    if [ "$WP2SHELL_CROSSSITE_GROUP_CONFIRMED" = "1" ]; then
        minimum=${WP2SHELL_CROSSSITE_MIN_OWNERS_CONFIRMED:-2}
    fi
    case $minimum in
        ''|*[!0-9]*) minimum=3 ;;
    esac
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
        log_debug "Kruisvergelijking slaat $WP2SHELL_CROSSSITE_GROUP_HASH over, het bestand hoort bij een gedeelde bibliotheek"
        return 0
    fi
    if [ "$WP2SHELL_CROSSSITE_GROUP_PACKAGE_ONLY" = "1" ] &&
        [ "$WP2SHELL_CROSSSITE_GROUP_SIGNATURE_COUNT" -le 1 ]; then
        log_debug "Kruisvergelijking slaat $WP2SHELL_CROSSSITE_GROUP_HASH over, dit is een gedeelde plugin of thema op steeds hetzelfde pad"
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
    local severity owners examples prefix=''
    severity=$(crosssite_group_severity)
    owners=$(crosssite_group_owner_list)
    examples=$(crosssite_group_example_list)
    if [ "$WP2SHELL_CROSSSITE_GROUP_TRUNCATED" = "1" ]; then
        prefix='minstens '
    fi
    local scope_note
    scope_note="Alleen bestanden die op hun eigen site al zelfstandig als verdacht waren aangemerkt komen in deze vergelijking terecht. Zonder dat filter zou de complete WordPress-core en elke veelgebruikte plugin op iedere site met zichzelf overeenkomen en zou een treffer niets betekenen."
    local match_note
    match_note="Er is vergeleken op sha256 en niet op pad, want dezelfde dropper krijgt op elke site een andere naam."
    local quarantine_note
    quarantine_note="Deze categorie wordt nooit automatisch in quarantaine gezet, ook niet met clean --apply."
    local counts
    counts="Bij elkaar $WP2SHELL_CROSSSITE_GROUP_OCCURRENCES voorkomen(s) op $prefix$WP2SHELL_CROSSSITE_GROUP_SITE_COUNT site(s), verdeeld over $prefix$WP2SHELL_CROSSSITE_GROUP_SIGNATURE_COUNT verschillend(e) pad(en)."
    if [ "$WP2SHELL_CROSSSITE_GROUP_CONFIRMED" = "1" ]; then
        record_finding \
            "severity=$severity" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=cross-site-confirmed-hash" \
            "title=Bevestigd kwaadaardig bestand staat bij $prefix$WP2SHELL_CROSSSITE_GROUP_OWNER_COUNT verschillende klanten" \
            "detail=Dit bestand is op minstens een site als bevestigd kwaadaardig aangemerkt, en exact dezelfde sha256 staat ook op installaties van andere systeemgebruikers: $owners. $counts $scope_note $match_note Wat deze bevinding toevoegt boven de losse bevindingen is de accountgrens: een losse bevinding zegt dat een site besmet is, deze zegt dat hetzelfde bestand tot bij andere klanten is gekomen die administratief niets met elkaar te maken hebben. Dat past bij een besmetting die zich over de server verplaatst en niet bij een enkele site die van buitenaf geraakt is. Voorbeeldpaden: $examples. $quarantine_note" \
            "evidence=sha256 $WP2SHELL_CROSSSITE_GROUP_HASH, $prefix$WP2SHELL_CROSSSITE_GROUP_OWNER_COUNT eigenaren, $prefix$WP2SHELL_CROSSSITE_GROUP_SITE_COUNT sites" \
            "remediation=Behandel alle genoemde installaties als gecompromitteerd, zet de genoemde bestanden na een geslaagde backup in quarantaine, en zoek de gedeelde weg tussen deze accounts, bijvoorbeeld een schrijfbare gedeelde map, hergebruikte FTP-gegevens of een beheerpaneel met te ruime rechten."
        return 0
    fi
    record_finding \
        "severity=$severity" \
        "confidence=$CONFIDENCE_HEURISTIC" \
        "category=cross-site-identical-file" \
        "title=Zelfde verdachte bestand bij $prefix$WP2SHELL_CROSSSITE_GROUP_OWNER_COUNT verschillende klanten" \
        "detail=Een bestand met sha256 $WP2SHELL_CROSSSITE_GROUP_HASH komt byte voor byte terug op installaties van $prefix$WP2SHELL_CROSSSITE_GROUP_OWNER_COUNT verschillende systeemgebruikers: $owners. $counts $scope_note $match_note Gedeelde pakketten zijn hier al afgevangen: een bestand dat bij elk voorkomen op precies hetzelfde pad binnen dezelfde plugin- of themamap staat is overgeslagen, net als alles in een vendor-map, want een premium plugin of een gedeelde bibliotheek heeft op elke site vanzelf dezelfde hash. Wat overblijft is precies wat de losse bevindingen niet kunnen zeggen: die melden per site een twijfelgeval, terwijl identieke inhoud bij klanten die niets met elkaar te maken hebben niet door toeval of door een gedeelde pluginversie te verklaren is. Voorbeeldpaden: $examples. Dit blijft een heuristiek en is geen bewijs, bekijk de inhoud handmatig voordat er iets verplaatst wordt. $quarantine_note" \
        "evidence=sha256 $WP2SHELL_CROSSSITE_GROUP_HASH, $prefix$WP2SHELL_CROSSSITE_GROUP_OWNER_COUNT eigenaren, $prefix$WP2SHELL_CROSSSITE_GROUP_SITE_COUNT sites" \
        "remediation=Bekijk een van de genoemde bestanden handmatig. Blijkt het kwaadaardig, behandel dan alle genoemde installaties als besmet en zoek de gedeelde weg tussen deze accounts. Blijkt het legitiem, neem het pad dan op in WP2SHELL_ALLOWLIST_PATHS zodat het bij een volgende run niet terugkomt."
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
        "title=De vergelijking tussen de sites is niet uitgevoerd" \
        "detail=Het vergelijken van verdachte bestanden tussen de installaties op deze server heeft niet gedraaid. Reden: $reason. Malware die tegelijk bij meerdere klanten staat wordt in deze run dus niet als zodanig herkend. Het ontbreken van kruisverbanden in dit rapport is hier geen uitspraak over de server." \
        "remediation=Controleer de rechten op de tijdelijke map en draai de scan opnieuw."
    return 0
}

crosssite_report_degraded() {
    record_finding \
        "severity=$SEVERITY_MEDIUM" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=cross-site-correlation-incomplete" \
        "title=De vergelijking tussen de sites is onvolledig" \
        "detail=Een deel van de verdachte bestanden kon niet meedoen aan de vergelijking tussen de sites, bijvoorbeeld omdat er geen sha256 beschikbaar was of omdat de eigenaar van een installatie niet vast te stellen was. De vergelijking heeft wel gedraaid, maar over een onvolledige verzameling. Een uitkomst zonder kruisverbanden mag daarom niet gelezen worden als bewijs dat er niets tussen de klanten gedeeld wordt." \
        "remediation=Bekijk in het runlogboek de regels over de kruisvergelijking en draai de scan opnieuw als root."
    return 0
}

crosssite_report_suppressed() {
    record_finding \
        "severity=$SEVERITY_MEDIUM" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=cross-site-correlation-truncated" \
        "title=$WP2SHELL_CROSSSITE_SUPPRESSED kruisverbanden zijn niet apart uitgeschreven" \
        "detail=Er zijn meer bestanden gevonden die bij verschillende klanten identiek terugkomen dan er los gemeld worden. Boven de grens van ${WP2SHELL_CROSSSITE_MAX_REPORTED_HASHES:-50} bevindingen is de rest alleen geteld, zodat het rapport leesbaar blijft. Deze $WP2SHELL_CROSSSITE_SUPPRESSED gevallen zijn dus wel gevonden en niet weggevallen." \
        "remediation=Behandel dit als een serverbreed incident en verhoog WP2SHELL_CROSSSITE_MAX_REPORTED_HASHES als de volledige lijst nodig is."
    return 0
}

crosssite_report() {
    WP2SHELL_CROSSSITE_REPORTED=0
    WP2SHELL_CROSSSITE_SUPPRESSED=0
    if ! crosssite_ensure_state_directory; then
        crosssite_report_unavailable "de werkmap voor de vergelijking kon niet veilig aangemaakt worden"
        return 0
    fi
    local degraded=0
    if [ -e "$WP2SHELL_CROSSSITE_STATE_DIR/degraded" ]; then
        degraded=1
    fi
    local state="$WP2SHELL_CROSSSITE_STATE_DIR/candidates"
    if [ ! -s "$state" ]; then
        log_debug "Geen kandidaten voor de vergelijking tussen sites"
        if [ "$degraded" = "1" ]; then
            crosssite_report_degraded
        fi
        crosssite_discard_state
        return 0
    fi
    local sorted status=0
    if ! sorted=$(mktemp -t wp2shell-crosssite-sorted.XXXXXXXX); then
        crosssite_report_unavailable "er kon geen tijdelijk bestand aangemaakt worden om de kandidaten te sorteren"
        crosssite_discard_state
        return 0
    fi
    register_temp_cleanup "$sorted"
    LC_ALL=C "${WP2SHELL_SORT:-sort}" -u -- "$state" > "$sorted" 2>/dev/null || status=$?
    if [ "$status" -ne 0 ]; then
        crosssite_report_unavailable "het sorteren van de kandidaten gaf exitcode $status"
        rm -f -- "$sorted"
        crosssite_discard_state
        return 0
    fi
    crosssite_group_reset
    local hash='' owner='' site_encoded='' file_encoded='' signature='' vendor='' flag=''
    while IFS=' ' read -r hash owner site_encoded file_encoded signature vendor flag ||
        [ -n "$hash" ]; do
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
    log_info "Vergelijking tussen sites klaar, $WP2SHELL_CROSSSITE_REPORTED kruisverband(en) gemeld"
    crosssite_discard_state
    return 0
}
