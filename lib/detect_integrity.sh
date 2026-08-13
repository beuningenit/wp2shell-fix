WP2SHELL_DETECT_INTEGRITY_LOADED=1

WP2SHELL_INTEGRITY_WORK_DIR=""
WP2SHELL_INTEGRITY_SHA256_TOOL=""
WP2SHELL_INTEGRITY_ENGINE_STATE=""

WP2SHELL_INTEGRITY_PACKAGES_TOTAL=0
WP2SHELL_INTEGRITY_PACKAGES_VERIFIED=0
WP2SHELL_INTEGRITY_PACKAGES_UNVERIFIED=0
WP2SHELL_INTEGRITY_UNVERIFIED_LABELS=()
WP2SHELL_INTEGRITY_OVERSIZED=()
WP2SHELL_INTEGRITY_HASH_FAILURES=()
WP2SHELL_INTEGRITY_CORE_STATE="niet uitgevoerd"

WP2SHELL_INTEGRITY_MATCHED=0
WP2SHELL_INTEGRITY_MODIFIED=0
WP2SHELL_INTEGRITY_MISSING=0
WP2SHELL_INTEGRITY_EXTRA_OTHER=0
WP2SHELL_INTEGRITY_SCOPE_TOTAL=0
WP2SHELL_INTEGRITY_EXAMINED=0
WP2SHELL_INTEGRITY_TRUNCATED=0
WP2SHELL_INTEGRITY_WALK_FAILED=0
WP2SHELL_INTEGRITY_UNHASHED=0
WP2SHELL_INTEGRITY_EXTRA_PHP=()
WP2SHELL_INTEGRITY_MISSING_SAMPLE=()
WP2SHELL_INTEGRITY_EXTRA_OTHER_SAMPLE=()
WP2SHELL_INTEGRITY_MODIFIED_REPORTED=0
WP2SHELL_INTEGRITY_DOUBT=0
WP2SHELL_INTEGRITY_DOUBT_REASON=""
WP2SHELL_INTEGRITY_EXTRA_CONFIDENCE=""
WP2SHELL_INTEGRITY_EXTRA_REASON=""
WP2SHELL_INTEGRITY_REFERENCE_LISTING=""
WP2SHELL_INTEGRITY_REFERENCE_READY=0
WP2SHELL_INTEGRITY_MANIFEST_REASON=""

declare -gA WP2SHELL_INTEGRITY_MANIFEST=()
declare -gA WP2SHELL_INTEGRITY_SEEN=()

detect_integrity_sha256_tool() {
    if [ -n "$WP2SHELL_INTEGRITY_SHA256_TOOL" ]; then
        printf '%s' "$WP2SHELL_INTEGRITY_SHA256_TOOL"
        return 0
    fi
    if have_command sha256sum; then
        WP2SHELL_INTEGRITY_SHA256_TOOL=sha256sum
    elif have_command openssl; then
        WP2SHELL_INTEGRITY_SHA256_TOOL=openssl
    else
        WP2SHELL_INTEGRITY_SHA256_TOOL=none
    fi
    printf '%s' "$WP2SHELL_INTEGRITY_SHA256_TOOL"
    return 0
}

detect_integrity_file_sha256() {
    local target=$1 tool output=''
    tool=$(detect_integrity_sha256_tool)
    case $tool in
        sha256sum)
            output=$(sha256sum -- "$target" 2>/dev/null) || return 1
            output=${output%% *}
            output=${output#\\}
            ;;
        openssl)
            output=$(openssl dgst -sha256 -- "$target" 2>/dev/null) || return 1
            output=${output##* }
            ;;
        *)
            return 1
            ;;
    esac
    output=${output,,}
    if [ "${#output}" -ne 64 ]; then
        return 1
    fi
    case $output in
        *[!0-9a-f]*) return 1 ;;
    esac
    printf '%s' "$output"
    return 0
}

detect_integrity_work_file() {
    printf '%s/%s' "$WP2SHELL_INTEGRITY_WORK_DIR" "$1"
    return 0
}

detect_integrity_prepare_work_dir() {
    if [ -n "$WP2SHELL_INTEGRITY_WORK_DIR" ] && [ -d "$WP2SHELL_INTEGRITY_WORK_DIR" ]; then
        return 0
    fi
    local created
    created=$(make_temp_dir wp2shell-integrity) || return 1
    register_temp_cleanup "$created"
    WP2SHELL_INTEGRITY_WORK_DIR="$created"
    return 0
}

detect_integrity_release_work_dir() {
    if [ -z "$WP2SHELL_INTEGRITY_WORK_DIR" ]; then
        return 0
    fi
    case $WP2SHELL_INTEGRITY_WORK_DIR in
        */wp2shell-integrity.*) rm -rf -- "$WP2SHELL_INTEGRITY_WORK_DIR" 2>/dev/null || true ;;
    esac
    WP2SHELL_INTEGRITY_WORK_DIR=""
    return 0
}

detect_integrity_shorten() {
    local raw=$1 limit=$2
    raw=${raw//$'\n'/ }
    raw=${raw//$'\t'/ }
    if [ "${#raw}" -gt "$limit" ]; then
        raw="${raw:0:$limit}..."
    fi
    printf '%s' "$raw"
    return 0
}

detect_integrity_join_sample() {
    local first=1 entry
    for entry in "$@"; do
        if [ "$first" = "1" ]; then
            first=0
        else
            printf ', '
        fi
        printf '%s' "$entry"
    done
    return 0
}

detect_integrity_is_executable_php_name() {
    local lower=${1,,}
    case $lower in
        *.php|*.phtml|*.pht|*.php3|*.php4|*.php5|*.php6|*.php7|*.php8|*.phps|*.phar) return 0 ;;
    esac
    return 1
}

detect_integrity_has_php_open_tag() {
    "${WP2SHELL_GREP:-grep}" -F -q -m1 -e '<?' -- "$1" 2>/dev/null
}

detect_integrity_is_silence_guard() {
    local candidate=$1 size=$2
    local base=${candidate##*/}
    case ${base,,} in
        index.php|index.html|index.htm) ;;
        *) return 1 ;;
    esac
    case $size in
        ''|*[!0-9]*) return 1 ;;
    esac
    if [ "$size" -gt 400 ]; then
        return 1
    fi
    local content
    content=$(head -c 400 -- "$candidate" 2>/dev/null) || return 1
    local protocol_single protocol_double
    protocol_single="\$_SERVER['SERVER_PROTOCOL']"
    protocol_double='$_SERVER["SERVER_PROTOCOL"]'
    content=${content//"$protocol_single"/}
    content=${content//"$protocol_double"/}
    local forbidden
    for forbidden in 'eval' 'base64' 'assert' 'gzinflate' 'gzuncompress' 'str_rot13' 'include' \
        'require' 'file_get_contents' 'file_put_contents' 'fopen' 'shell_exec' 'passthru' \
        'proc_open' 'popen' 'system' 'exec' 'preg_replace' 'create_function' 'call_user_func' \
        'move_uploaded_file' '$_POST' '$_GET' '$_REQUEST' '$_COOKIE' '$_FILES' '$_ENV' '$GLOBALS' \
        '$_SERVER' 'curl_' 'socket_' 'chmod' 'unlink' 'hex2bin' 'pack(' '\x'
    do
        case $content in
            *"$forbidden"*) return 1 ;;
        esac
    done
    return 0
}

detect_integrity_version_is_plausible() {
    local value=$1
    case $value in
        '') return 1 ;;
        trunk|TRUNK) return 1 ;;
        *[!0-9A-Za-z._-]*) return 1 ;;
        [0-9]*|v[0-9]*) ;;
        *) return 1 ;;
    esac
    if [ "${#value}" -gt 32 ]; then
        return 1
    fi
    return 0
}

detect_integrity_slug_is_plausible() {
    local slug=$1
    case $slug in
        ''|.|..) return 1 ;;
        *[!a-z0-9._-]*) return 1 ;;
        .*) return 1 ;;
    esac
    if [ "${#slug}" -gt 64 ]; then
        return 1
    fi
    return 0
}

detect_integrity_header_value() {
    local file=$1 header=$2 limit=$3
    if [ ! -r "$file" ]; then
        return 1
    fi
    local size
    size=$(file_size_bytes "$file") || size=0
    case $size in
        ''|*[!0-9]*) size=0 ;;
    esac
    if [ "$size" -eq 0 ] || [ "$size" -gt 1048576 ]; then
        return 1
    fi
    local pattern="^[[:space:]*/#@]*${header}:[[:space:]]*(.+)$"
    local line value='' count=0
    while IFS= read -r line || [ -n "$line" ]; do
        count=$((count + 1))
        if [ "$count" -gt "$limit" ]; then
            break
        fi
        line=${line%$'\r'}
        if [[ $line =~ $pattern ]]; then
            value=${BASH_REMATCH[1]}
            break
        fi
    done < "$file"
    if [ -z "$value" ]; then
        return 1
    fi
    printf '%s' "$value"
    return 0
}

detect_integrity_header_token() {
    local raw
    if ! raw=$(detect_integrity_header_value "$1" "$2" "$3"); then
        return 1
    fi
    raw=${raw%%[[:space:]]*}
    if [ -z "$raw" ]; then
        return 1
    fi
    printf '%s' "$raw"
    return 0
}

detect_integrity_core_locale() {
    local site_path=$1
    local file="$site_path/wp-includes/version.php"
    if [ ! -r "$file" ]; then
        return 1
    fi
    local line value='' count=0
    while IFS= read -r line || [ -n "$line" ]; do
        count=$((count + 1))
        if [ "$count" -gt 400 ]; then
            break
        fi
        if [[ $line =~ \$wp_local_package[[:space:]]*=[[:space:]]*[\'\"]([A-Za-z_]+)[\'\"] ]]; then
            value=${BASH_REMATCH[1]}
            break
        fi
    done < "$file"
    if [ -z "$value" ]; then
        return 1
    fi
    printf '%s' "$value"
    return 0
}

detect_integrity_core_version() {
    local site_path=$1
    local file="$site_path/wp-includes/version.php"
    if [ ! -r "$file" ]; then
        return 1
    fi
    local pattern="\\\$wp_version[[:space:]]*=[[:space:]]*['\"]([^'\"]+)['\"]"
    local line value='' count=0
    while IFS= read -r line || [ -n "$line" ]; do
        count=$((count + 1))
        if [ "$count" -gt 400 ]; then
            break
        fi
        if [[ $line =~ $pattern ]]; then
            value=${BASH_REMATCH[1]}
            break
        fi
    done < "$file"
    if ! detect_integrity_version_is_plausible "$value"; then
        return 1
    fi
    printf '%s' "$value"
    return 0
}

detect_integrity_plugin_main_file() {
    local plugin_dir=$1
    local listing status=0 candidate
    listing=$(detect_integrity_work_file mainfiles.list)
    : > "$listing"
    "${WP2SHELL_FIND:-find}" -P "$plugin_dir" -maxdepth 1 -type f -iname '*.php' -print0 \
        > "$listing" 2>/dev/null || status=$?
    if [ "$status" -ne 0 ]; then
        log_debug "Kon de hoofdbestanden van $plugin_dir niet opsommen, exitcode $status"
    fi
    while IFS= read -r -d '' candidate; do
        if detect_integrity_header_value "$candidate" 'Plugin Name' 150 >/dev/null; then
            printf '%s' "${candidate##*/}"
            return 0
        fi
    done < "$listing"
    return 1
}

detect_integrity_engine_is_available() {
    local name
    for name in reference_engine_available reference_manifest_for; do
        if ! declare -F "$name" >/dev/null 2>&1; then
            WP2SHELL_INTEGRITY_ENGINE_STATE="module-ontbreekt"
            return 1
        fi
    done
    if ! reference_engine_available; then
        WP2SHELL_INTEGRITY_ENGINE_STATE="engine-onbruikbaar"
        return 1
    fi
    WP2SHELL_INTEGRITY_ENGINE_STATE="beschikbaar"
    return 0
}

detect_integrity_report_engine_gap() {
    local site_path=$1 detail
    case $WP2SHELL_INTEGRITY_ENGINE_STATE in
        module-ontbreekt)
            detail="De module lib/reference.sh is niet geladen, dus er zijn geen referentiemanifesten om tegen te vergelijken. De integriteitscontrole op core, plugins en themas is volledig overgeslagen."
            ;;
        *)
            detail="De referentie-engine meldt dat hij niet bruikbaar is, bijvoorbeeld omdat unzip of curl ontbreekt of omdat de cachemap niet beschrijfbaar is. De integriteitscontrole op core, plugins en themas is daarom volledig overgeslagen."
            ;;
    esac
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_MEDIUM" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=integrity-engine-unavailable" \
        "title=De integriteitscontrole tegen de officiele pakketten is niet uitgevoerd" \
        "detail=$detail Het uitblijven van bevindingen uit deze controle zegt hier dus niets: deze installatie is op dit punt niet gecontroleerd en mag niet als schoon gelden." \
        "evidence=$WP2SHELL_INTEGRITY_ENGINE_STATE" \
        "remediation=Controleer of lib/reference.sh geladen wordt, of unzip en curl aanwezig zijn en of de cachemap van de referentie-engine bruikbaar is, en draai de scan opnieuw."
    return 0
}

detect_integrity_report_missing_hash_tool() {
    local site_path=$1
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_MEDIUM" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=integrity-hash-tool-missing" \
        "title=Er is geen sha256-tool, de integriteitscontrole is overgeslagen" \
        "detail=Zonder sha256sum of openssl kunnen bestanden niet met de referentiemanifesten vergeleken worden. De vergelijking van core, plugins en themas is volledig overgeslagen en deze installatie is op dat punt niet gecontroleerd." \
        "remediation=Installeer coreutils of openssl op deze server en draai de scan opnieuw."
    return 0
}

detect_integrity_note_unverified() {
    local label=$1
    WP2SHELL_INTEGRITY_PACKAGES_UNVERIFIED=$((WP2SHELL_INTEGRITY_PACKAGES_UNVERIFIED + 1))
    if [ "${#WP2SHELL_INTEGRITY_UNVERIFIED_LABELS[@]}" -lt 40 ]; then
        WP2SHELL_INTEGRITY_UNVERIFIED_LABELS+=("$label")
    fi
    return 0
}

detect_integrity_report_unverified_package() {
    local site_path=$1 kind=$2 label=$3 package_dir=$4 reason=$5 extra=$6
    local severity="$SEVERITY_INFO" category=integrity-unverified
    local context="Dit is geen aanwijzing voor besmetting en ook geen vrijbrief: premiumcode, maatwerk en zelfgebouwde childthemas staan niet op wordpress.org en zijn hier per definitie niet te vergelijken."
    if [ "$kind" = "core" ]; then
        severity="$SEVERITY_MEDIUM"
        category=integrity-core-unverified
        context="Voor core weegt dit zwaarder dan voor een plugin of thema: de kernbestanden horen altijd exact overeen te komen met een officiele uitgave, dus het ontbreken van die vergelijking is een echt gat in deze scan."
    fi
    detect_integrity_note_unverified "$label"
    record_finding \
        "site=$site_path" \
        "severity=$severity" \
        "confidence=$CONFIDENCE_HEURISTIC" \
        "category=$category" \
        "title=$label is niet met een officieel pakket vergeleken" \
        "detail=Reden: $reason.$extra $context De inhoud van deze map is in deze controle niet tegen een referentie gehouden, dus hier geldt geen uitspraak, ook geen positieve." \
        "file=$package_dir" \
        "evidence=$label" \
        "remediation=Vergelijk deze map handmatig met een schone kopie van de leverancier of met een backup van voor 17 juli 2026."
    return 0
}

detect_integrity_kind_noun() {
    case $1 in
        core) printf 'de WordPress core' ;;
        plugin) printf 'de plugin' ;;
        theme) printf 'het thema' ;;
        *) printf 'het pakket' ;;
    esac
    return 0
}

detect_integrity_path_in_scope() {
    local kind=$1 relative=$2
    if [ "$kind" != "core" ]; then
        return 0
    fi
    case $relative in
        wp-admin/*|wp-includes/*) return 0 ;;
        */*) return 1 ;;
        *) return 0 ;;
    esac
}

detect_integrity_is_known_runtime_artifact() {
    local kind=$1 relative=$2
    local base=${relative##*/}
    case ${base,,} in
        .htaccess|.htpasswd|.user.ini|php.ini|error_log|.ds_store|thumbs.db|desktop.ini) return 0 ;;
    esac
    if [ "$kind" = "core" ]; then
        case $relative in
            wp-config.php|wordfence-waf.php) return 0 ;;
            robots.txt|ads.txt|favicon.ico|sitemap.xml|sitemap_index.xml) return 0 ;;
        esac
    fi
    return 1
}

detect_integrity_is_runtime_directory() {
    local relative=$1
    case $relative in
        cache/*|*/cache/*) return 0 ;;
        logs/*|*/logs/*|log/*|*/log/*) return 0 ;;
        tmp/*|*/tmp/*|temp/*|*/temp/*) return 0 ;;
        uploads/*|*/uploads/*) return 0 ;;
        backup/*|*/backup/*|backups/*|*/backups/*) return 0 ;;
    esac
    return 1
}

detect_integrity_reset_package_state() {
    WP2SHELL_INTEGRITY_MANIFEST=()
    WP2SHELL_INTEGRITY_SEEN=()
    WP2SHELL_INTEGRITY_MATCHED=0
    WP2SHELL_INTEGRITY_MODIFIED=0
    WP2SHELL_INTEGRITY_MISSING=0
    WP2SHELL_INTEGRITY_EXTRA_OTHER=0
    WP2SHELL_INTEGRITY_SCOPE_TOTAL=0
    WP2SHELL_INTEGRITY_EXAMINED=0
    WP2SHELL_INTEGRITY_TRUNCATED=0
    WP2SHELL_INTEGRITY_WALK_FAILED=0
    WP2SHELL_INTEGRITY_UNHASHED=0
    WP2SHELL_INTEGRITY_EXTRA_PHP=()
    WP2SHELL_INTEGRITY_MISSING_SAMPLE=()
    WP2SHELL_INTEGRITY_EXTRA_OTHER_SAMPLE=()
    WP2SHELL_INTEGRITY_MODIFIED_REPORTED=0
    WP2SHELL_INTEGRITY_DOUBT=0
    WP2SHELL_INTEGRITY_DOUBT_REASON=""
    WP2SHELL_INTEGRITY_REFERENCE_READY=0
    WP2SHELL_INTEGRITY_REFERENCE_LISTING=""
    return 0
}

detect_integrity_load_manifest() {
    local manifest_file=$1 kind=$2
    WP2SHELL_INTEGRITY_MANIFEST_REASON="het referentiemanifest bevatte geen bruikbare regels"
    if [ ! -r "$manifest_file" ]; then
        WP2SHELL_INTEGRITY_MANIFEST_REASON="het referentiemanifest was niet leesbaar"
        return 1
    fi
    local hash rel loaded=0 scope=0 seen_lines=0
    while IFS=$'\t' read -r hash rel || [ -n "$hash" ]; do
        rel=${rel%$'\r'}
        rel=${rel#./}
        if [ -z "$hash" ] || [ -z "$rel" ]; then
            continue
        fi
        seen_lines=$((seen_lines + 1))
        hash=${hash,,}
        if [ "${#hash}" -ne 64 ]; then
            continue
        fi
        case $hash in
            *[!0-9a-f]*) continue ;;
        esac
        case $rel in
            /*|../*|*/../*) continue ;;
        esac
        WP2SHELL_INTEGRITY_MANIFEST["$rel"]="$hash"
        loaded=$((loaded + 1))
        if detect_integrity_path_in_scope "$kind" "$rel"; then
            scope=$((scope + 1))
        fi
    done < "$manifest_file"
    WP2SHELL_INTEGRITY_SCOPE_TOTAL=$scope
    if [ "$loaded" -eq 0 ]; then
        if [ "$seen_lines" -gt 0 ]; then
            WP2SHELL_INTEGRITY_MANIFEST_REASON="het referentiemanifest bevatte $seen_lines regels, maar geen enkele met een sha256 van 64 hexadecimale tekens gevolgd door een tab en een relatief pad"
        fi
        return 1
    fi
    log_debug "Manifest $manifest_file geladen: $loaded regels, $scope binnen bereik"
    return 0
}

detect_integrity_identity_is_confirmed() {
    local kind=$1 main_file=$2
    case $kind in
        core)
            if [ -n "${WP2SHELL_INTEGRITY_MANIFEST["wp-includes/version.php"]:-}" ] &&
                [ -n "${WP2SHELL_INTEGRITY_MANIFEST["wp-settings.php"]:-}" ]; then
                return 0
            fi
            return 1
            ;;
        plugin)
            if [ -n "$main_file" ] && [ -n "${WP2SHELL_INTEGRITY_MANIFEST["$main_file"]:-}" ]; then
                return 0
            fi
            return 1
            ;;
        theme)
            if [ -n "${WP2SHELL_INTEGRITY_MANIFEST["style.css"]:-}" ]; then
                return 0
            fi
            return 1
            ;;
    esac
    return 1
}

detect_integrity_collect_files() {
    local kind=$1 root=$2 destination=$3
    local status=0 part=0
    : > "$destination"
    if [ "$kind" = "core" ]; then
        "${WP2SHELL_FIND:-find}" -P "$root" -maxdepth 1 -xdev -type f -print0 \
            >> "$destination" 2>/dev/null || part=$?
        if [ "$part" -ne 0 ]; then
            status=$part
        fi
        local sub
        for sub in wp-admin wp-includes; do
            if [ ! -d "$root/$sub" ]; then
                continue
            fi
            part=0
            "${WP2SHELL_FIND:-find}" -P "$root/$sub" -xdev -type f -print0 \
                >> "$destination" 2>/dev/null || part=$?
            if [ "$part" -ne 0 ]; then
                status=$part
            fi
        done
        return "$status"
    fi
    "${WP2SHELL_FIND:-find}" -P "$root" -xdev \
        '(' -name '.git' -o -name '.svn' -o -name 'node_modules' ')' -prune -o \
        -type f -print0 >> "$destination" 2>/dev/null || status=$?
    return "$status"
}

detect_integrity_prepare_reference_listing() {
    local kind=$1 root=$2
    if [ "$WP2SHELL_INTEGRITY_REFERENCE_READY" = "1" ]; then
        return 0
    fi
    WP2SHELL_INTEGRITY_REFERENCE_READY=1
    local listing status=0
    listing=$(detect_integrity_work_file references.list)
    : > "$listing"
    if [ "$kind" = "core" ]; then
        "${WP2SHELL_FIND:-find}" -P "$root" -maxdepth 1 -xdev -type f -print0 \
            > "$listing" 2>/dev/null || status=$?
    else
        "${WP2SHELL_FIND:-find}" -P "$root" -xdev \
            '(' -name '.git' -o -name '.svn' -o -name 'node_modules' ')' -prune -o \
            -type f '(' -iname '*.php' -o -iname '*.inc' -o -iname '*.json' -o -iname '*.txt' \
            -o -iname '*.md' -o -iname '*.js' -o -iname '*.map' -o -iname '*.css' \
            -o -iname '*.ini' -o -iname '*.yml' ')' -print0 > "$listing" 2>/dev/null || status=$?
    fi
    if [ "$status" -ne 0 ]; then
        log_debug "Kon de verwijzingenlijst voor $root niet volledig opbouwen, exitcode $status"
        WP2SHELL_INTEGRITY_REFERENCE_LISTING=""
        return 1
    fi
    WP2SHELL_INTEGRITY_REFERENCE_LISTING="$listing"
    return 0
}

detect_integrity_stem_is_referenced() {
    local kind=$1 root=$2 candidate=$3
    local base=${candidate##*/}
    local stem=${base%.*}
    if [ "${#stem}" -lt 3 ]; then
        return 0
    fi
    if ! detect_integrity_prepare_reference_listing "$kind" "$root"; then
        return 0
    fi
    if [ -z "$WP2SHELL_INTEGRITY_REFERENCE_LISTING" ]; then
        return 0
    fi
    local budget=${WP2SHELL_INTEGRITY_REFERENCE_SCAN_MAX_FILES:-400}
    local size_cap=524288
    local checked=0 other size
    while IFS= read -r -d '' other; do
        if [ "$other" = "$candidate" ]; then
            continue
        fi
        checked=$((checked + 1))
        if [ "$checked" -gt "$budget" ]; then
            log_debug "Budget voor de verwijzingscontrole op is bij $candidate"
            return 0
        fi
        size=$(file_size_bytes "$other") || size=0
        case $size in
            ''|*[!0-9]*) size=0 ;;
        esac
        if [ "$size" -eq 0 ] || [ "$size" -gt "$size_cap" ]; then
            continue
        fi
        if "${WP2SHELL_GREP:-grep}" -F -q -m1 -e "$stem" -- "$other" 2>/dev/null; then
            return 0
        fi
    done < "$WP2SHELL_INTEGRITY_REFERENCE_LISTING"
    return 1
}

detect_integrity_theme_hot_file_note() {
    local kind=$1 relative=$2
    if [ "$kind" != "theme" ]; then
        return 1
    fi
    local base=${relative##*/}
    case ${base,,} in
        functions.php|404.php|header.php|footer.php|index.php|page.php|single.php|archive.php|comments.php|searchform.php|sidebar.php)
            printf ' Let hier extra op: %s is een van de klassieke plekken voor een backdoor in een thema, omdat het bestand bij vrijwel elke paginaweergave geladen wordt, ook voor bezoekers die niet ingelogd zijn. Themas hadden tot nu toe geen enkele checksumdekking in deze toolkit, dus dit is de eerste controle die hier ooit naar gekeken heeft.' "$base"
            return 0
            ;;
    esac
    return 1
}

detect_integrity_report_modified_file() {
    local site_path=$1 kind=$2 label=$3 candidate=$4 relative=$5 actual=$6 expected=$7 version=$8
    local cap=${WP2SHELL_INTEGRITY_MAX_FINDINGS_PER_PACKAGE:-25}
    if [ "$WP2SHELL_INTEGRITY_MODIFIED_REPORTED" -ge "$cap" ]; then
        return 0
    fi
    WP2SHELL_INTEGRITY_MODIFIED_REPORTED=$((WP2SHELL_INTEGRITY_MODIFIED_REPORTED + 1))
    local noun theme_note=''
    noun=$(detect_integrity_kind_noun "$kind")
    theme_note=$(detect_integrity_theme_hot_file_note "$kind" "$relative") || theme_note=''
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_HIGH" \
        "confidence=$CONFIDENCE_HEURISTIC" \
        "category=integrity-file-modified" \
        "title=Gewijzigd bestand in $label: $relative" \
        "detail=Dit bestand hoort bij $label versie $version, maar de inhoud wijkt af van het officiele pakket van wordpress.org. Een afwijking is nog geen besmetting: een beheerder kan het bestand zelf aangepast hebben, een update kan halverwege afgebroken zijn, en een hoster kan een patch toegepast hebben. Het blijft wel de plek waar een geinjecteerde loader zich verstopt.$theme_note" \
        "file=$candidate" \
        "evidence=aangetroffen sha256 $actual, verwacht $expected" \
        "remediation=Vergelijk dit bestand met het officiele pakket en herstel het door $noun opnieuw te installeren. Verplaats een gewijzigd bestand niet naar quarantaine, want de site heeft het nodig."
    return 0
}

detect_integrity_report_modified_overflow() {
    local site_path=$1 label=$2
    local cap=${WP2SHELL_INTEGRITY_MAX_FINDINGS_PER_PACKAGE:-25}
    if [ "$WP2SHELL_INTEGRITY_MODIFIED" -le "$cap" ]; then
        return 0
    fi
    local rest=$((WP2SHELL_INTEGRITY_MODIFIED - cap))
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_HIGH" \
        "confidence=$CONFIDENCE_HEURISTIC" \
        "category=integrity-file-modified-overflow" \
        "title=Nog $rest gewijzigde bestanden in $label niet apart gemeld" \
        "detail=In $label wijken $WP2SHELL_INTEGRITY_MODIFIED bestanden af van het officiele pakket. De eerste $cap zijn hierboven per bestand gemeld, de overige $rest niet, om het rapport leesbaar te houden. Ze zijn wel meegeteld en deze map is dus niet als schoon te beschouwen. Zoveel afwijkingen wijzen meestal op een verkeerd geraden versie of een handmatig aangepaste kopie, en soms op een grondige injectie." \
        "remediation=Herinstalleer dit pakket vanaf de officiele bron en scan daarna opnieuw."
    return 0
}

detect_integrity_report_extra_php() {
    local site_path=$1 kind=$2 label=$3 candidate=$4 relative=$5 version=$6
    local theme_note='' identity_note dropper_note
    theme_note=$(detect_integrity_theme_hot_file_note "$kind" "$relative") || theme_note=''
    if [ "$kind" = "core" ]; then
        identity_note="het manifest bevat de kernbestanden wp-includes/version.php en wp-settings.php, dus het is werkelijk een corepakket"
        dropper_note="De webroot en de mappen wp-admin en wp-includes horen uitsluitend bestanden uit de officiele uitgave te bevatten, en een dropper belandt precies hier."
    else
        identity_note="de identiteit van het pakket is bevestigd via het hoofdbestand op schijf"
        dropper_note="Een dropper in een plugin- of themamap belandt precies hier."
    fi
    if [ "$WP2SHELL_INTEGRITY_EXTRA_CONFIDENCE" = "$CONFIDENCE_HIGH" ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_CRITICAL" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=integrity-extra-executable-php" \
            "title=Uitvoerbaar PHP-bestand dat niet in het officiele pakket zit: $relative" \
            "detail=Dit bestand staat in de map van $label versie $version en komt in het officiele pakket van wordpress.org niet voor. De uitspraak steunt op meerdere onafhankelijke structurele signalen tegelijk: $identity_note, de overige bestanden komen wel met het pakket overeen, het bestand bevat een PHP-openingstag, het is geen lege index.php en de naam wordt nergens anders in dit pakket genoemd, dus geen enkel bestand van het pakket kan het laden. $dropper_note$theme_note" \
            "file=$candidate" \
            "evidence=$relative" \
            "remediation=Zet dit bestand in quarantaine, bekijk de toegangslogs op verzoeken naar dit pad en herinstalleer daarna het pakket."
        return 0
    fi
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_HIGH" \
        "confidence=$CONFIDENCE_HEURISTIC" \
        "category=integrity-extra-executable-php-review" \
        "title=Onbekend PHP-bestand in $label: $relative" \
        "detail=Dit bestand staat in de map van $label versie $version en komt niet voor in het officiele pakket. Het is bewust niet als bevestigd gemeld, want: $WP2SHELL_INTEGRITY_EXTRA_REASON. Daarmee kan dit net zo goed legitieme code van de beheerder of van het pakket zelf zijn. Er wordt hier niets automatisch verplaatst.$theme_note" \
        "file=$candidate" \
        "evidence=$relative" \
        "remediation=Bekijk de inhoud van dit bestand handmatig voordat er iets verwijderd wordt."
    return 0
}

detect_integrity_extra_php_decision() {
    local kind=$1 root=$2 candidate=$3 relative=$4 size=$5 identity=$6
    WP2SHELL_INTEGRITY_EXTRA_CONFIDENCE="$CONFIDENCE_HEURISTIC"
    WP2SHELL_INTEGRITY_EXTRA_REASON=""
    if [ "$WP2SHELL_INTEGRITY_DOUBT" = "1" ]; then
        WP2SHELL_INTEGRITY_EXTRA_REASON="$WP2SHELL_INTEGRITY_DOUBT_REASON"
        return 0
    fi
    if [ "$identity" != "1" ]; then
        WP2SHELL_INTEGRITY_EXTRA_REASON="de identiteit van dit pakket kon niet bevestigd worden, het hoofdbestand op schijf komt niet overeen met het opgehaalde pakket"
        return 0
    fi
    if detect_integrity_is_silence_guard "$candidate" "$size"; then
        WP2SHELL_INTEGRITY_EXTRA_REASON="het is een lege index.php zonder uitvoerende code, het bekende bestand dat directory listing tegenhoudt"
        return 0
    fi
    if ! detect_integrity_has_php_open_tag "$candidate"; then
        WP2SHELL_INTEGRITY_EXTRA_REASON="het bestand heeft wel een PHP-extensie maar bevat geen PHP-openingstag"
        return 0
    fi
    if detect_integrity_is_runtime_directory "$relative"; then
        WP2SHELL_INTEGRITY_EXTRA_REASON="het bestand staat in een map die pakketten zelf tijdens gebruik vullen, zoals cache, logs of tmp"
        return 0
    fi
    if detect_integrity_stem_is_referenced "$kind" "$root" "$candidate"; then
        WP2SHELL_INTEGRITY_EXTRA_REASON="de bestandsnaam wordt genoemd in een ander bestand van dit pakket, dus de code kan het bewust laden en verwijderen zou iets kunnen breken"
        return 0
    fi
    if [ "$kind" = "core" ]; then
        case $relative in
            wp-admin/*|wp-includes/*) ;;
            *)
                WP2SHELL_INTEGRITY_EXTRA_REASON="het bestand staat los in de webroot en niet in wp-admin of wp-includes. Daar staan ook eigen bestanden van de klant en soms een tweede applicatie, dus dit is geen bevestigde dropper"
                return 0
                ;;
        esac
    fi
    WP2SHELL_INTEGRITY_EXTRA_CONFIDENCE="$CONFIDENCE_HIGH"
    return 0
}

detect_integrity_evaluate_doubt() {
    local kind=$1 identity=$2
    local min_percent=${WP2SHELL_INTEGRITY_MIN_MATCH_PERCENT:-60}
    local max_extra=${WP2SHELL_INTEGRITY_MAX_HIGH_EXTRA_FILES:-10}
    local extra_php=${#WP2SHELL_INTEGRITY_EXTRA_PHP[@]}
    if [ "$WP2SHELL_INTEGRITY_TRUNCATED" = "1" ]; then
        WP2SHELL_INTEGRITY_DOUBT=1
        WP2SHELL_INTEGRITY_DOUBT_REASON="de map bevat meer bestanden dan de ingestelde limiet, dus de vergelijking is onvolledig"
        return 0
    fi
    if [ "$WP2SHELL_INTEGRITY_WALK_FAILED" = "1" ]; then
        WP2SHELL_INTEGRITY_DOUBT=1
        WP2SHELL_INTEGRITY_DOUBT_REASON="niet alle paden in deze map waren leesbaar, dus de vergelijking is onvolledig"
        return 0
    fi
    if [ "$identity" != "1" ]; then
        WP2SHELL_INTEGRITY_DOUBT=1
        WP2SHELL_INTEGRITY_DOUBT_REASON="de identiteit van het pakket kon niet bevestigd worden"
        return 0
    fi
    if [ "$WP2SHELL_INTEGRITY_SCOPE_TOTAL" -le 0 ]; then
        WP2SHELL_INTEGRITY_DOUBT=1
        WP2SHELL_INTEGRITY_DOUBT_REASON="het referentiemanifest bevatte geen bestanden binnen het gecontroleerde bereik, er is dus feitelijk niets vergeleken"
        return 0
    fi
    local percent=$((WP2SHELL_INTEGRITY_MATCHED * 100 / WP2SHELL_INTEGRITY_SCOPE_TOTAL))
    if [ "$percent" -lt "$min_percent" ]; then
        WP2SHELL_INTEGRITY_DOUBT=1
        WP2SHELL_INTEGRITY_DOUBT_REASON="slechts $percent procent van de bestanden uit het referentiepakket is ongewijzigd teruggevonden, dus waarschijnlijk is er tegen de verkeerde versie of het verkeerde pakket vergeleken"
        return 0
    fi
    if [ "$extra_php" -gt "$max_extra" ]; then
        WP2SHELL_INTEGRITY_DOUBT=1
        WP2SHELL_INTEGRITY_DOUBT_REASON="er staan $extra_php uitvoerbare PHP-bestanden in deze map die niet in het pakket zitten, en zoveel onbekende bestanden duiden vaker op een hernoemde map of een afwijkende uitgave dan op evenveel droppers"
        return 0
    fi
    if [ "$kind" = "core" ] && [ "$WP2SHELL_INTEGRITY_UNHASHED" -gt 0 ]; then
        WP2SHELL_INTEGRITY_DOUBT=1
        WP2SHELL_INTEGRITY_DOUBT_REASON="er zijn $WP2SHELL_INTEGRITY_UNHASHED kernbestanden niet gehasht, dus de corevergelijking is onvolledig"
        return 0
    fi
    return 0
}

detect_integrity_report_doubt() {
    local site_path=$1 label=$2 package_dir=$3
    if [ "$WP2SHELL_INTEGRITY_DOUBT" != "1" ]; then
        return 0
    fi
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_MEDIUM" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=integrity-comparison-doubtful" \
        "title=De vergelijking van $label is niet betrouwbaar genoeg voor een harde uitspraak" \
        "detail=Reden: $WP2SHELL_INTEGRITY_DOUBT_REASON. Alle afwijkingen in deze map zijn daarom als heuristisch gemeld en er wordt niets automatisch verplaatst. Tegelijk mag deze map niet als gecontroleerd gelden: de vergelijking heeft geen bruikbare uitspraak opgeleverd." \
        "file=$package_dir" \
        "evidence=$WP2SHELL_INTEGRITY_MATCHED van $WP2SHELL_INTEGRITY_SCOPE_TOTAL bestanden ongewijzigd, $WP2SHELL_INTEGRITY_MODIFIED gewijzigd, ${#WP2SHELL_INTEGRITY_EXTRA_PHP[@]} onbekende PHP-bestanden" \
        "remediation=Stel handmatig vast welke versie en welk pakket hier hoort en vergelijk daarmee opnieuw."
    return 0
}

detect_integrity_report_missing_files() {
    local site_path=$1 kind=$2 label=$3 package_dir=$4 version=$5
    if [ "$WP2SHELL_INTEGRITY_MISSING" -eq 0 ]; then
        return 0
    fi
    if [ "$WP2SHELL_INTEGRITY_DOUBT" = "1" ]; then
        log_debug "Ontbrekende bestanden in $label niet apart gemeld, de vergelijking is al als onbetrouwbaar gemeld"
        return 0
    fi
    local sample=''
    if [ "${#WP2SHELL_INTEGRITY_MISSING_SAMPLE[@]}" -gt 0 ]; then
        sample=$(detect_integrity_join_sample "${WP2SHELL_INTEGRITY_MISSING_SAMPLE[@]}")
    fi
    local noun
    noun=$(detect_integrity_kind_noun "$kind")
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_LOW" \
        "confidence=$CONFIDENCE_HEURISTIC" \
        "category=integrity-missing-files" \
        "title=$WP2SHELL_INTEGRITY_MISSING bestanden uit het officiele pakket ontbreken in $label" \
        "detail=Deze bestanden zitten wel in het officiele pakket van $label versie $version maar staan niet op schijf. Dat is meestal het werk van een hardeningscript of van een beheerder die readme.html, license.txt of een meegeleverd voorbeeldbestand heeft weggehaald. Ontbrekende bestanden zijn zelden een teken van besmetting, maar ze maken de installatie wel afwijkend van de officiele uitgave." \
        "file=$package_dir" \
        "evidence=$(detect_integrity_shorten "$sample" 400)" \
        "remediation=Controleer of het weghalen bewust gebeurd is. Installeer $noun opnieuw als de site zich vreemd gedraagt."
    return 0
}

detect_integrity_report_extra_other_files() {
    local site_path=$1 kind=$2 label=$3 package_dir=$4
    if [ "$WP2SHELL_INTEGRITY_EXTRA_OTHER" -eq 0 ]; then
        return 0
    fi
    if [ "$WP2SHELL_INTEGRITY_DOUBT" = "1" ]; then
        log_debug "Overige onbekende bestanden in $label niet apart gemeld, de vergelijking is al als onbetrouwbaar gemeld"
        return 0
    fi
    local sample=''
    if [ "${#WP2SHELL_INTEGRITY_EXTRA_OTHER_SAMPLE[@]}" -gt 0 ]; then
        sample=$(detect_integrity_join_sample "${WP2SHELL_INTEGRITY_EXTRA_OTHER_SAMPLE[@]}")
    fi
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_INFO" \
        "confidence=$CONFIDENCE_HEURISTIC" \
        "category=integrity-extra-other-files" \
        "title=$WP2SHELL_INTEGRITY_EXTRA_OTHER bestanden in $label zitten niet in het officiele pakket" \
        "detail=Dit zijn geen uitvoerbare PHP-bestanden. Een eigen logo, een aangepaste stylesheet, een vertaling of een achtergelaten zipbestand komt hier terecht en dat is volstrekt normaal. Deze melding is informatief en wordt nooit automatisch opgeruimd, want juist hier staan de bestanden van de klant." \
        "file=$package_dir" \
        "evidence=$(detect_integrity_shorten "$sample" 400)" \
        "remediation=Geen actie nodig, tenzij een van deze bestanden er niet thuishoort."
    return 0
}

detect_integrity_report_unhashed_files() {
    local site_path=$1 label=$2 package_dir=$3
    if [ "$WP2SHELL_INTEGRITY_UNHASHED" -eq 0 ]; then
        return 0
    fi
    local cap=${WP2SHELL_INTEGRITY_MAX_HASH_BYTES:-33554432}
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_MEDIUM" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=integrity-files-unhashed" \
        "title=$WP2SHELL_INTEGRITY_UNHASHED bestanden in $label zijn niet vergeleken" \
        "detail=Van deze bestanden kon geen sha256 berekend worden, omdat ze groter zijn dan de ingestelde grens van $cap bytes of omdat lezen mislukte. Ze staan wel in het referentiepakket, maar hun inhoud is niet gecontroleerd. Voor deze bestanden geldt dus geen uitspraak, ook geen positieve." \
        "file=$package_dir" \
        "remediation=Verhoog WP2SHELL_INTEGRITY_MAX_HASH_BYTES of controleer deze bestanden handmatig."
    return 0
}

detect_integrity_compare_tree() {
    local site_path=$1 kind=$2 label=$3 root=$4 version=$5 identity=$6
    local listing status=0
    listing=$(detect_integrity_work_file tree.list)
    detect_integrity_collect_files "$kind" "$root" "$listing" || status=$?
    if [ "$status" -ne 0 ]; then
        WP2SHELL_INTEGRITY_WALK_FAILED=1
        log_warn "Het doorlopen van $root gaf exitcode $status"
    fi
    local max_files=${WP2SHELL_INTEGRITY_MAX_FILES_PER_PACKAGE:-20000}
    local hash_cap=${WP2SHELL_INTEGRITY_MAX_HASH_BYTES:-33554432}
    local candidate relative expected actual size
    while IFS= read -r -d '' candidate; do
        relative=${candidate#"$root"/}
        if [ "$relative" = "$candidate" ]; then
            continue
        fi
        WP2SHELL_INTEGRITY_EXAMINED=$((WP2SHELL_INTEGRITY_EXAMINED + 1))
        if [ "$WP2SHELL_INTEGRITY_EXAMINED" -gt "$max_files" ]; then
            WP2SHELL_INTEGRITY_TRUNCATED=1
            break
        fi
        expected=${WP2SHELL_INTEGRITY_MANIFEST["$relative"]:-}
        if [ -n "$expected" ]; then
            WP2SHELL_INTEGRITY_SEEN["$relative"]=1
            if ! detect_integrity_path_in_scope "$kind" "$relative"; then
                continue
            fi
            size=$(file_size_bytes "$candidate") || size=0
            case $size in
                ''|*[!0-9]*) size=0 ;;
            esac
            if [ "$size" -gt "$hash_cap" ]; then
                WP2SHELL_INTEGRITY_UNHASHED=$((WP2SHELL_INTEGRITY_UNHASHED + 1))
                if [ "${#WP2SHELL_INTEGRITY_OVERSIZED[@]}" -lt 40 ]; then
                    WP2SHELL_INTEGRITY_OVERSIZED+=("$candidate")
                fi
                continue
            fi
            actual=$(detect_integrity_file_sha256 "$candidate") || actual=''
            if [ -z "$actual" ]; then
                WP2SHELL_INTEGRITY_UNHASHED=$((WP2SHELL_INTEGRITY_UNHASHED + 1))
                if [ "${#WP2SHELL_INTEGRITY_HASH_FAILURES[@]}" -lt 40 ]; then
                    WP2SHELL_INTEGRITY_HASH_FAILURES+=("$candidate")
                fi
                continue
            fi
            if [ "$actual" = "$expected" ]; then
                WP2SHELL_INTEGRITY_MATCHED=$((WP2SHELL_INTEGRITY_MATCHED + 1))
                continue
            fi
            WP2SHELL_INTEGRITY_MODIFIED=$((WP2SHELL_INTEGRITY_MODIFIED + 1))
            detect_integrity_report_modified_file "$site_path" "$kind" "$label" "$candidate" \
                "$relative" "$actual" "$expected" "$version"
            continue
        fi
        if ! detect_integrity_path_in_scope "$kind" "$relative"; then
            continue
        fi
        if detect_integrity_is_known_runtime_artifact "$kind" "$relative"; then
            continue
        fi
        if is_allowlisted_path "$candidate"; then
            continue
        fi
        if detect_integrity_is_executable_php_name "${candidate##*/}"; then
            WP2SHELL_INTEGRITY_EXTRA_PHP+=("$candidate")
            continue
        fi
        WP2SHELL_INTEGRITY_EXTRA_OTHER=$((WP2SHELL_INTEGRITY_EXTRA_OTHER + 1))
        if [ "${#WP2SHELL_INTEGRITY_EXTRA_OTHER_SAMPLE[@]}" -lt 8 ]; then
            WP2SHELL_INTEGRITY_EXTRA_OTHER_SAMPLE+=("$relative")
        fi
    done < "$listing"
    local entry
    if [ "${#WP2SHELL_INTEGRITY_MANIFEST[@]}" -gt 0 ]; then
        for entry in "${!WP2SHELL_INTEGRITY_MANIFEST[@]}"; do
            if [ -n "${WP2SHELL_INTEGRITY_SEEN["$entry"]:-}" ]; then
                continue
            fi
            if ! detect_integrity_path_in_scope "$kind" "$entry"; then
                continue
            fi
            WP2SHELL_INTEGRITY_MISSING=$((WP2SHELL_INTEGRITY_MISSING + 1))
            if [ "${#WP2SHELL_INTEGRITY_MISSING_SAMPLE[@]}" -lt 8 ]; then
                WP2SHELL_INTEGRITY_MISSING_SAMPLE+=("$entry")
            fi
        done
    fi
    detect_integrity_evaluate_doubt "$kind" "$identity"
    local extra_reported=0 cap=${WP2SHELL_INTEGRITY_MAX_FINDINGS_PER_PACKAGE:-25}
    if [ "${#WP2SHELL_INTEGRITY_EXTRA_PHP[@]}" -gt 0 ]; then
        for candidate in "${WP2SHELL_INTEGRITY_EXTRA_PHP[@]}"; do
            extra_reported=$((extra_reported + 1))
            if [ "$extra_reported" -gt "$cap" ]; then
                break
            fi
            relative=${candidate#"$root"/}
            size=$(file_size_bytes "$candidate") || size=0
            case $size in
                ''|*[!0-9]*) size=0 ;;
            esac
            detect_integrity_extra_php_decision "$kind" "$root" "$candidate" "$relative" "$size" "$identity"
            detect_integrity_report_extra_php "$site_path" "$kind" "$label" "$candidate" "$relative" "$version"
        done
    fi
    detect_integrity_report_doubt "$site_path" "$label" "$root"
    detect_integrity_report_modified_overflow "$site_path" "$label"
    detect_integrity_report_missing_files "$site_path" "$kind" "$label" "$root" "$version"
    detect_integrity_report_extra_other_files "$site_path" "$kind" "$label" "$root"
    detect_integrity_report_unhashed_files "$site_path" "$label" "$root"
    log_debug "Integriteit $label: $WP2SHELL_INTEGRITY_MATCHED gelijk, $WP2SHELL_INTEGRITY_MODIFIED gewijzigd, ${#WP2SHELL_INTEGRITY_EXTRA_PHP[@]} onbekende PHP, $WP2SHELL_INTEGRITY_MISSING ontbrekend"
    return 0
}

detect_integrity_check_package() {
    local site_path=$1 kind=$2 slug=$3 version=$4 root=$5 main_file=$6 label=$7
    WP2SHELL_INTEGRITY_PACKAGES_TOTAL=$((WP2SHELL_INTEGRITY_PACKAGES_TOTAL + 1))
    detect_integrity_reset_package_state
    local manifest='' locale_argument="$slug"
    if [ "$kind" = "core" ]; then
        locale_argument=$(detect_integrity_core_locale "$site_path") || locale_argument=''
        if [ -n "$locale_argument" ]; then
            log_debug "Core-taalversie uit version.php: $locale_argument"
        fi
    fi
    manifest=$(reference_manifest_for "$kind" "$locale_argument" "$version" 2>/dev/null) || manifest=''
    if [ -z "$manifest" ] || [ ! -r "$manifest" ]; then
        detect_integrity_report_unverified_package "$site_path" "$kind" "$label" "$root" \
            "de referentie-engine kon voor slug $slug versie $version geen pakket leveren, dat gebeurt bij premiumcode, bij maatwerk, bij een versie die de directory niet kent en ook wanneer het ophalen mislukte" \
            ""
        return 0
    fi
    if ! detect_integrity_load_manifest "$manifest" "$kind"; then
        detect_integrity_report_unverified_package "$site_path" "$kind" "$label" "$root" \
            "$WP2SHELL_INTEGRITY_MANIFEST_REASON" \
            " Een leeg of onleesbaar manifest is een fout in de referentie-engine en geen uitspraak over deze installatie."
        return 0
    fi
    local identity=0
    if detect_integrity_identity_is_confirmed "$kind" "$main_file"; then
        identity=1
    fi
    detect_integrity_compare_tree "$site_path" "$kind" "$label" "$root" "$version" "$identity"
    if [ "$WP2SHELL_INTEGRITY_DOUBT" = "1" ]; then
        detect_integrity_note_unverified "$label"
        return 0
    fi
    WP2SHELL_INTEGRITY_PACKAGES_VERIFIED=$((WP2SHELL_INTEGRITY_PACKAGES_VERIFIED + 1))
    return 0
}

detect_integrity_check_core() {
    local site_path=$1
    local version=''
    if ! version=$(detect_integrity_core_version "$site_path"); then
        WP2SHELL_INTEGRITY_CORE_STATE="versie onbekend, niet vergeleken"
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=integrity-core-version-unknown" \
            "title=De coreversie is niet uit wp-includes/version.php te lezen" \
            "detail=Zonder versienummer valt er geen referentiepakket op te halen, dus de kernbestanden van deze installatie zijn niet met de officiele uitgave vergeleken. Een ontbrekende of onleesbare version.php is op zichzelf al opvallend: het bestand hoort in elke WordPress-installatie te staan." \
            "file=$site_path/wp-includes/version.php" \
            "remediation=Controleer of dit een echte WordPress-installatie is en herstel version.php uit een schone kopie."
        return 0
    fi
    WP2SHELL_INTEGRITY_CORE_STATE="versie $version, vergeleken"
    detect_integrity_check_package "$site_path" core "" "$version" "$site_path" "" "core"
    if [ "$WP2SHELL_INTEGRITY_DOUBT" = "1" ]; then
        WP2SHELL_INTEGRITY_CORE_STATE="versie $version, vergelijking onbetrouwbaar"
    fi
    return 0
}

detect_integrity_check_plugin_directory() {
    local site_path=$1 plugin_dir=$2
    local name=${plugin_dir##*/}
    local slug=${name,,}
    local label="plugin $name"
    if ! detect_integrity_slug_is_plausible "$slug"; then
        WP2SHELL_INTEGRITY_PACKAGES_TOTAL=$((WP2SHELL_INTEGRITY_PACKAGES_TOTAL + 1))
        detect_integrity_report_unverified_package "$site_path" plugin "$label" "$plugin_dir" \
            "de mapnaam is geen bruikbare slug voor wordpress.org" \
            " Een mapnaam met vreemde tekens is geen bewijs, maar wel een reden om deze map handmatig te bekijken."
        return 0
    fi
    local main_file=''
    if ! main_file=$(detect_integrity_plugin_main_file "$plugin_dir"); then
        WP2SHELL_INTEGRITY_PACKAGES_TOTAL=$((WP2SHELL_INTEGRITY_PACKAGES_TOTAL + 1))
        detect_integrity_report_unverified_package "$site_path" plugin "$label" "$plugin_dir" \
            "er is in deze map geen PHP-bestand met een Plugin Name-header gevonden" \
            " Zonder die header is dit voor WordPress geen plugin. Dat komt voor bij een map met alleen data of een halve upload, en het is ook precies hoe een map met alleen een dropper eruitziet."
        return 0
    fi
    local version=''
    if ! version=$(detect_integrity_header_token "$plugin_dir/$main_file" 'Version' 150); then
        WP2SHELL_INTEGRITY_PACKAGES_TOTAL=$((WP2SHELL_INTEGRITY_PACKAGES_TOTAL + 1))
        detect_integrity_report_unverified_package "$site_path" plugin "$label" "$plugin_dir" \
            "het hoofdbestand $main_file heeft geen leesbare Version-header" \
            " Zonder versienummer is er geen referentiepakket op te halen."
        return 0
    fi
    if ! detect_integrity_version_is_plausible "$version"; then
        WP2SHELL_INTEGRITY_PACKAGES_TOTAL=$((WP2SHELL_INTEGRITY_PACKAGES_TOTAL + 1))
        detect_integrity_report_unverified_package "$site_path" plugin "$label" "$plugin_dir" \
            "de versie in het hoofdbestand is niet bruikbaar als versienummer" \
            " Aangetroffen waarde: $(detect_integrity_shorten "$version" 40)."
        return 0
    fi
    detect_integrity_check_package "$site_path" plugin "$slug" "$version" "$plugin_dir" "$main_file" "$label"
    return 0
}

detect_integrity_check_theme_directory() {
    local site_path=$1 theme_dir=$2
    local name=${theme_dir##*/}
    local slug=${name,,}
    local label="thema $name"
    local style="$theme_dir/style.css"
    if [ ! -r "$style" ]; then
        WP2SHELL_INTEGRITY_PACKAGES_TOTAL=$((WP2SHELL_INTEGRITY_PACKAGES_TOTAL + 1))
        detect_integrity_report_unverified_package "$site_path" theme "$label" "$theme_dir" \
            "er is geen leesbare style.css, en zonder dat bestand is dit voor WordPress geen thema" \
            " Een map zonder style.css onder wp-content/themes verdient een handmatige blik."
        return 0
    fi
    local child_note='' template=''
    if template=$(detect_integrity_header_token "$style" 'Template' 200); then
        child_note=" Dit is een childthema van $template, en childthemas zijn bijna altijd handwerk dat nergens in een directory staat."
        label="thema $name (childthema van $template)"
    fi
    if ! detect_integrity_slug_is_plausible "$slug"; then
        WP2SHELL_INTEGRITY_PACKAGES_TOTAL=$((WP2SHELL_INTEGRITY_PACKAGES_TOTAL + 1))
        detect_integrity_report_unverified_package "$site_path" theme "$label" "$theme_dir" \
            "de mapnaam is geen bruikbare slug voor wordpress.org" "$child_note"
        return 0
    fi
    local version=''
    if ! version=$(detect_integrity_header_token "$style" 'Version' 200); then
        WP2SHELL_INTEGRITY_PACKAGES_TOTAL=$((WP2SHELL_INTEGRITY_PACKAGES_TOTAL + 1))
        detect_integrity_report_unverified_package "$site_path" theme "$label" "$theme_dir" \
            "style.css heeft geen leesbare Version-header" \
            "$child_note Zonder versienummer is er geen referentiepakket op te halen."
        return 0
    fi
    if ! detect_integrity_version_is_plausible "$version"; then
        WP2SHELL_INTEGRITY_PACKAGES_TOTAL=$((WP2SHELL_INTEGRITY_PACKAGES_TOTAL + 1))
        detect_integrity_report_unverified_package "$site_path" theme "$label" "$theme_dir" \
            "de versie in style.css is niet bruikbaar als versienummer" \
            "$child_note Aangetroffen waarde: $(detect_integrity_shorten "$version" 40)."
        return 0
    fi
    detect_integrity_check_package "$site_path" theme "$slug" "$version" "$theme_dir" "" "$label"
    return 0
}

detect_integrity_check_package_directories() {
    local site_path=$1 kind=$2 base=$3
    if [ ! -d "$base" ]; then
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_INFO" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=integrity-package-dir-missing" \
            "title=De map $base bestaat niet, er is niets vergeleken" \
            "detail=Deze installatie heeft de verwachte map niet op de standaardplek staan, bijvoorbeeld omdat WP_CONTENT_DIR verlegd is. De integriteitscontrole voor deze categorie is daardoor overgeslagen en zegt hier niets." \
            "remediation=Controleer waar wp-content voor deze installatie staat en pas de scan daarop aan."
        return 0
    fi
    local listing status=0 entry
    listing=$(detect_integrity_work_file "packages-$kind.list")
    : > "$listing"
    "${WP2SHELL_FIND:-find}" -P "$base" -mindepth 1 -maxdepth 1 -xdev -type d -print0 \
        > "$listing" 2>/dev/null || status=$?
    if [ "$status" -ne 0 ]; then
        log_warn "Kon $base niet volledig uitlezen, exitcode $status"
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=integrity-scan-incomplete" \
            "title=De inhoud van $base kon niet volledig opgesomd worden" \
            "detail=Het opsommen van de mappen gaf exitcode $status. Er kunnen plugins of themas gemist zijn, dus het uitblijven van bevindingen betekent hier niet dat alles gecontroleerd is." \
            "remediation=Controleer de rechten op deze map en draai de scan opnieuw."
    fi
    while IFS= read -r -d '' entry; do
        if [ "$kind" = "plugin" ]; then
            detect_integrity_check_plugin_directory "$site_path" "$entry"
        else
            detect_integrity_check_theme_directory "$site_path" "$entry"
        fi
    done < "$listing"
    return 0
}

detect_integrity_report_unhashed_summary() {
    local site_path=$1
    local oversized=${#WP2SHELL_INTEGRITY_OVERSIZED[@]}
    local failures=${#WP2SHELL_INTEGRITY_HASH_FAILURES[@]}
    if [ "$oversized" -eq 0 ] && [ "$failures" -eq 0 ]; then
        return 0
    fi
    local sample='' entry shown=0
    for entry in "${WP2SHELL_INTEGRITY_OVERSIZED[@]+"${WP2SHELL_INTEGRITY_OVERSIZED[@]}"}" \
        "${WP2SHELL_INTEGRITY_HASH_FAILURES[@]+"${WP2SHELL_INTEGRITY_HASH_FAILURES[@]}"}"
    do
        if [ "$shown" -ge 5 ]; then
            break
        fi
        sample="$sample $entry"
        shown=$((shown + 1))
    done
    local cap=${WP2SHELL_INTEGRITY_MAX_HASH_BYTES:-33554432}
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_LOW" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=integrity-unhashed-summary" \
        "title=$oversized te grote en $failures onleesbare bestanden zijn niet vergeleken" \
        "detail=Bestanden boven de grens van $cap bytes zijn overgeslagen bij het hashen, en van de onleesbare bestanden kon geen sha256 berekend worden. Voor deze bestanden is er geen uitspraak: ze zijn niet goedgekeurd, ze zijn alleen niet bekeken." \
        "evidence=$(detect_integrity_shorten "${sample# }" 400)" \
        "remediation=Verhoog WP2SHELL_INTEGRITY_MAX_HASH_BYTES of controleer deze bestanden handmatig."
    return 0
}

detect_integrity_report_summary() {
    local site_path=$1
    local labels='geen'
    if [ "${#WP2SHELL_INTEGRITY_UNVERIFIED_LABELS[@]}" -gt 0 ]; then
        labels=$(detect_integrity_join_sample "${WP2SHELL_INTEGRITY_UNVERIFIED_LABELS[@]}")
    fi
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_INFO" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=integrity-summary" \
        "title=Integriteitscontrole afgerond: $WP2SHELL_INTEGRITY_PACKAGES_VERIFIED van $WP2SHELL_INTEGRITY_PACKAGES_TOTAL pakketten vergeleken" \
        "detail=Core is beoordeeld als $WP2SHELL_INTEGRITY_CORE_STATE. Van de $WP2SHELL_INTEGRITY_PACKAGES_TOTAL pakketten zijn er $WP2SHELL_INTEGRITY_PACKAGES_VERIFIED daadwerkelijk tegen een officieel pakket gelegd en $WP2SHELL_INTEGRITY_PACKAGES_UNVERIFIED niet. Deze controle werkt puur vanaf schijf en heeft geen WP-CLI en geen database nodig, dus hij levert ook een uitspraak op als WP-CLI niet kan draaien. Buiten bereik blijven: losse PHP-bestanden direct in wp-content/plugins, de mappen wp-content/mu-plugins en wp-content/uploads, alles onder wp-content bij de corevergelijking, en de mappen .git, .svn en node_modules." \
        "evidence=$(detect_integrity_shorten "niet vergeleken: $labels" 600)" \
        "remediation=Bekijk de niet vergeleken pakketten handmatig, want daar geldt geen enkele uitspraak over."
    if [ "$WP2SHELL_INTEGRITY_PACKAGES_UNVERIFIED" -eq 0 ]; then
        return 0
    fi
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_LOW" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=integrity-coverage-partial" \
        "title=$WP2SHELL_INTEGRITY_PACKAGES_UNVERIFIED pakketten konden niet met een officieel pakket vergeleken worden" \
        "detail=Voor deze pakketten is er geen referentie beschikbaar of was de vergelijking niet betrouwbaar genoeg. Dat is normaal voor premiumplugins, maatwerk en zelfgebouwde childthemas, en het gebeurt ook wanneer het ophalen bij wordpress.org mislukt. De uitkomst van deze controle dekt deze installatie dus maar gedeeltelijk en een rapport zonder bevindingen mag hier niet als schoon gelezen worden." \
        "evidence=$(detect_integrity_shorten "$labels" 600)" \
        "remediation=Vergelijk deze pakketten handmatig met een schone kopie van de leverancier."
    return 0
}

detect_integrity_reset_site_state() {
    WP2SHELL_INTEGRITY_PACKAGES_TOTAL=0
    WP2SHELL_INTEGRITY_PACKAGES_VERIFIED=0
    WP2SHELL_INTEGRITY_PACKAGES_UNVERIFIED=0
    WP2SHELL_INTEGRITY_UNVERIFIED_LABELS=()
    WP2SHELL_INTEGRITY_OVERSIZED=()
    WP2SHELL_INTEGRITY_HASH_FAILURES=()
    WP2SHELL_INTEGRITY_CORE_STATE="niet uitgevoerd"
    detect_integrity_reset_package_state
    return 0
}

detect_integrity_for_site() {
    local site_path=${1:-}
    local owner_user=${2:-}
    if [ -z "$site_path" ]; then
        log_error "detect_integrity_for_site is aangeroepen zonder sitepad"
        return "$EXIT_INTERNAL"
    fi
    site_path=${site_path%/}
    if [ ! -d "$site_path" ]; then
        log_error "Sitepad bestaat niet of is geen map: $site_path"
        return "$EXIT_INTERNAL"
    fi
    detect_integrity_reset_site_state
    log_debug "Integriteitscontrole gestart voor $site_path, eigenaar ${owner_user:-onbekend}"
    if [ "$(detect_integrity_sha256_tool)" = "none" ]; then
        detect_integrity_report_missing_hash_tool "$site_path"
        return 0
    fi
    if ! detect_integrity_engine_is_available; then
        detect_integrity_report_engine_gap "$site_path"
        return 0
    fi
    if ! detect_integrity_prepare_work_dir; then
        log_error "Kan geen werkmap aanmaken voor de integriteitscontrole van $site_path"
        record_finding \
            "site=$site_path" \
            "severity=$SEVERITY_MEDIUM" \
            "confidence=$CONFIDENCE_HIGH" \
            "category=integrity-workdir-unavailable" \
            "title=De integriteitscontrole kon geen werkmap aanmaken" \
            "detail=Zonder tijdelijke werkmap kan de vergelijking met de officiele pakketten niet draaien. Deze installatie is op dat punt niet gecontroleerd." \
            "remediation=Controleer de vrije ruimte en de rechten op de tijdelijke map van deze server."
        return "$EXIT_INTERNAL"
    fi
    detect_integrity_check_core "$site_path"
    detect_integrity_check_package_directories "$site_path" plugin "$site_path/wp-content/plugins"
    detect_integrity_check_package_directories "$site_path" theme "$site_path/wp-content/themes"
    detect_integrity_report_unhashed_summary "$site_path"
    detect_integrity_report_summary "$site_path"
    detect_integrity_release_work_dir
    return 0
}
