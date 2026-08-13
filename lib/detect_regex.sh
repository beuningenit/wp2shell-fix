WP2SHELL_DETECT_REGEX_LOADED=1

WP2SHELL_DETECT_REGEX_LIB_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd) || WP2SHELL_DETECT_REGEX_LIB_DIR=""

WP2SHELL_REGEX_PATTERNS_LOADED=0
WP2SHELL_REGEX_LOAD_FAILED=0
WP2SHELL_REGEX_LOAD_DETAIL=""
WP2SHELL_REGEX_SOURCE_FILE=""
WP2SHELL_REGEX_GATE_FILE=""
WP2SHELL_REGEX_STRONG_GATE_FILE=""
WP2SHELL_REGEX_PREFIX_FILE=""
WP2SHELL_REGEX_SPAN_SUPPORTED=0
WP2SHELL_REGEX_SPAN_ARGS=()
WP2SHELL_REGEX_IDS=()
WP2SHELL_REGEX_MATCH_IDS=()
WP2SHELL_REGEX_SUPPRESSED_COUNT=0
WP2SHELL_REGEX_EVIDENCE_BYTES=4000

declare -gA WP2SHELL_REGEX_EXPRESSION=()
declare -gA WP2SHELL_REGEX_CATEGORY=()
declare -gA WP2SHELL_REGEX_CONFIDENCE=()
declare -gA WP2SHELL_REGEX_ONCE=()

detect_regex_ioc_directory() {
    if [ -n "${WP2SHELL_IOC_DIR:-}" ] && [ -d "$WP2SHELL_IOC_DIR" ]; then
        printf '%s' "$WP2SHELL_IOC_DIR"
        return 0
    fi
    if [ -n "${WP2SHELL_ROOT:-}" ] && [ -d "$WP2SHELL_ROOT/config/iocs" ]; then
        printf '%s' "$WP2SHELL_ROOT/config/iocs"
        return 0
    fi
    if [ -n "$WP2SHELL_DETECT_REGEX_LIB_DIR" ] && [ -d "$WP2SHELL_DETECT_REGEX_LIB_DIR/../config/iocs" ]; then
        printf '%s' "$WP2SHELL_DETECT_REGEX_LIB_DIR/../config/iocs"
        return 0
    fi
    return 1
}

detect_regex_category_label() {
    case $1 in
        input-eval) printf 'eval op invoer uit het verzoek' ;;
        input-assert) printf 'assert op invoer uit het verzoek' ;;
        decoded-exec) printf 'eval of assert op een gedecodeerde of uitgepakte waarde' ;;
        array-function-exec) printf 'eval van een functienaam uit een array' ;;
        preg-replace-eval) printf 'preg_replace met de e-modifier' ;;
        input-variable-function) printf 'variabele functie opgebouwd uit een superglobal' ;;
        input-decode) printf 'uitpakfunctie rechtstreeks op invoer uit het verzoek' ;;
        computed-superglobal) printf 'superglobal aangeroepen via een samengestelde naam' ;;
        concat-variable-name) printf 'variabelenaam samengesteld uit losse tekstdelen' ;;
        reversed-function-name) printf 'omgekeerd geschreven functienaam' ;;
        fragment-assembly) printf 'functienaam opgebouwd uit losse korte toewijzingen' ;;
        selfhealing-dropper) printf 'kopieeractie die een PHP-bestand in wp-content plaatst' ;;
        input-base64) printf 'base64_decode rechtstreeks op invoer uit het verzoek' ;;
        packed-payload) printf 'lange base64-blob die direct een decoder in gaat' ;;
        variable-variable-index) printf 'variabele variabele met een berekende index' ;;
        string-concat-obfuscation) printf 'tekst opgebouwd uit een reeks korte losse stukjes' ;;
        hex-escape-run) printf 'lange reeks hex-escapes' ;;
        chr-chain) printf 'tekenopbouw met chr en hexdec' ;;
        upload-path-from-request) printf 'uploadpad opgebouwd uit de naam die de bezoeker meestuurt' ;;
        cookie-to-sink) printf 'cookiewaarde die een uitvoerende functie in gaat' ;;
        goto-obfuscation) printf 'goto-sprong, in gewone PHP vrijwel nooit gebruikt' ;;
        image-code-include) printf 'code ingeladen vanuit een afbeeldings- of tekstbestand' ;;
        error-suppression) printf 'onderdrukte foutmeldingen rond een gevoelige functie' ;;
        timelimit-off) printf 'tijdslimiet uitgezet' ;;
        *) printf 'niet nader benoemd patroon (%s)' "$1" ;;
    esac
    return 0
}

detect_regex_category_is_conclusive() {
    case $1 in
        input-eval) return 0 ;;
    esac
    return 1
}

detect_regex_confidence_is_valid() {
    case $1 in
        high|medium|low) return 0 ;;
    esac
    return 1
}

detect_regex_is_scannable_name() {
    local lower=${1,,}
    case $lower in
        *.php|*.phtml|*.pht|*.php3|*.php4|*.php5|*.php6|*.php7|*.php8|*.phps|*.phar) return 0 ;;
        *.inc|*.txt|*.dat|*.ini|*.md) return 0 ;;
    esac
    return 1
}

detect_regex_name_runs_as_php() {
    local lower=${1,,}
    case $lower in
        *.php|*.phtml|*.pht|*.php3|*.php4|*.php5|*.php6|*.php7|*.php8|*.phps|*.phar) return 0 ;;
        *.inc) return 0 ;;
    esac
    return 1
}

detect_regex_evidence_snippet() {
    local raw=$1
    local limit=${WP2SHELL_HEURISTIC_EVIDENCE_CHARS:-200}
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

detect_regex_probe_span_support() {
    local status=0
    printf 'a\nb' | "${WP2SHELL_GREP:-grep}" -z -E -q -e 'a.b' 2>/dev/null || status=$?
    if [ "$status" -eq 0 ]; then
        WP2SHELL_REGEX_SPAN_SUPPORTED=1
        WP2SHELL_REGEX_SPAN_ARGS=(-z)
        return 0
    fi
    WP2SHELL_REGEX_SPAN_SUPPORTED=0
    WP2SHELL_REGEX_SPAN_ARGS=()
    log_warn "Deze grep kan geen patronen over regelgrenzen heen toepassen, de regex-laag draait in regelmodus"
    return 1
}

detect_regex_load_patterns() {
    local source_file=$1
    if [ ! -r "$source_file" ]; then
        WP2SHELL_REGEX_LOAD_DETAIL="Het bestand $source_file ontbreekt of is niet leesbaar."
        log_error "Regexpatronen ontbreken of zijn onleesbaar: $source_file"
        return 1
    fi
    local gate_file strong_gate_file
    gate_file=$(mktemp -t wp2shell-regex-gate.XXXXXXXX) || return 1
    register_temp_cleanup "$gate_file"
    : > "$gate_file"
    strong_gate_file=$(mktemp -t wp2shell-regex-strong.XXXXXXXX) || return 1
    register_temp_cleanup "$strong_gate_file"
    : > "$strong_gate_file"
    local line category confidence expression identifier status
    local loaded=0 invalid=0 index=0
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%$'\r'}
        case $line in
            ''|'#'*) continue ;;
        esac
        IFS=: read -r category confidence expression <<<"$line"
        if [ -z "$category" ] || [ -z "$confidence" ] || [ -z "$expression" ]; then
            invalid=$((invalid + 1))
            log_warn "Onbruikbare regel in $source_file: $line"
            continue
        fi
        if ! detect_regex_confidence_is_valid "$confidence"; then
            invalid=$((invalid + 1))
            log_warn "Onbekend vertrouwensniveau $confidence in $source_file, regel overgeslagen"
            continue
        fi
        status=0
        "${WP2SHELL_GREP:-grep}" -E -q -e "$expression" -- /dev/null 2>/dev/null || status=$?
        if [ "$status" -gt 1 ]; then
            invalid=$((invalid + 1))
            log_warn "Ongeldige expressie in $source_file, regel overgeslagen: $expression"
            continue
        fi
        index=$((index + 1))
        identifier="pattern$index"
        WP2SHELL_REGEX_EXPRESSION["$identifier"]="$expression"
        WP2SHELL_REGEX_CATEGORY["$identifier"]="$category"
        WP2SHELL_REGEX_CONFIDENCE["$identifier"]="$confidence"
        WP2SHELL_REGEX_IDS+=("$identifier")
        if [ "$confidence" != "low" ]; then
            printf '%s\n' "$expression" >> "$gate_file"
        fi
        if [ "$confidence" = "high" ]; then
            printf '%s\n' "$expression" >> "$strong_gate_file"
        fi
        loaded=$((loaded + 1))
    done < "$source_file"
    if [ "$loaded" -eq 0 ] || [ ! -s "$gate_file" ] || [ ! -s "$strong_gate_file" ]; then
        WP2SHELL_REGEX_LOAD_DETAIL="Uit $source_file kwam geen bruikbaar patroon voor elk van de vertrouwensniveaus."
        log_error "Geen bruikbare regexpatronen gelezen uit $source_file"
        rm -f -- "$gate_file" "$strong_gate_file"
        return 1
    fi
    if [ "$invalid" -gt 0 ]; then
        log_warn "$invalid regels uit $source_file zijn overgeslagen"
    fi
    WP2SHELL_REGEX_GATE_FILE="$gate_file"
    WP2SHELL_REGEX_STRONG_GATE_FILE="$strong_gate_file"
    WP2SHELL_REGEX_SOURCE_FILE="$source_file"
    log_debug "$loaded regexpatronen geladen uit $source_file"
    return 0
}

detect_regex_load_patterns_once() {
    if [ "$WP2SHELL_REGEX_PATTERNS_LOADED" = "1" ]; then
        return 0
    fi
    WP2SHELL_REGEX_PATTERNS_LOADED=1
    local ioc_dir
    if ! ioc_dir=$(detect_regex_ioc_directory); then
        WP2SHELL_REGEX_LOAD_FAILED=1
        WP2SHELL_REGEX_LOAD_DETAIL="De map config/iocs is niet gevonden."
        log_error "Geen IOC-map gevonden, de regex-laag is niet beschikbaar"
        return 1
    fi
    if ! detect_regex_load_patterns "$ioc_dir/code-patterns-regex.txt"; then
        WP2SHELL_REGEX_LOAD_FAILED=1
        return 1
    fi
    detect_regex_probe_span_support || true
    return 0
}

detect_regex_note_once() {
    local key=$1
    if [ -n "${WP2SHELL_REGEX_ONCE[$key]:-}" ]; then
        return 1
    fi
    WP2SHELL_REGEX_ONCE["$key"]=1
    return 0
}

detect_regex_report_pattern_gap() {
    local site_path=$1
    if [ "$WP2SHELL_REGEX_LOAD_FAILED" != "1" ]; then
        return 0
    fi
    if ! detect_regex_note_once "patterns|$site_path"; then
        return 0
    fi
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_MEDIUM" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=regex-patterns-missing" \
        "title=De regexpatronen konden niet geladen worden" \
        "detail=De patroonlaag met reguliere expressies is voor deze installatie niet gedraaid. $WP2SHELL_REGEX_LOAD_DETAIL Deze laag vangt juist de varianten met afwijkende spatiering die de letterlijke patronen missen, dus het uitblijven van bevindingen uit deze laag zegt hier niets over de toestand van de site." \
        "remediation=Controleer of config/iocs/code-patterns-regex.txt aanwezig en leesbaar is en draai de scan opnieuw."
    return 0
}

detect_regex_report_span_gap() {
    local site_path=$1
    if [ "$WP2SHELL_REGEX_SPAN_SUPPORTED" = "1" ]; then
        return 0
    fi
    if ! detect_regex_note_once "span|$site_path"; then
        return 0
    fi
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_LOW" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=regex-multiline-unavailable" \
        "title=De regex-laag kan niet over regelgrenzen heen zoeken" \
        "detail=De gebruikte grep ondersteunt de NUL-recordmodus niet zoals GNU grep dat doet. De patronen zijn daarom per regel toegepast. Patronen die twee kenmerken op enige afstand van elkaar combineren, zoals een cookiewaarde die verderop een uitvoerende functie in gaat, zijn op deze installatie dus niet gecontroleerd." \
        "remediation=Zorg dat GNU grep beschikbaar is en dat resolve_external_tools die versie kiest, en draai de scan opnieuw."
    return 0
}

detect_regex_report_unscanned() {
    local site_path=$1 candidate=$2 kind=$3 reason=$4
    log_warn "Regexcontrole niet uitgevoerd op $candidate: $reason"
    if ! detect_regex_note_once "unscanned|$kind|$site_path"; then
        return 0
    fi
    record_finding \
        "site=$site_path" \
        "severity=$SEVERITY_MEDIUM" \
        "confidence=$CONFIDENCE_HIGH" \
        "category=regex-scan-incomplete" \
        "title=Niet elk bestand is door de regex-laag gehaald" \
        "detail=Minstens een bestand in deze installatie is niet door de patroonlaag met reguliere expressies gekomen. Reden: $reason. Deze melding wordt per soort een keer vastgelegd, elk afzonderlijk geval staat in het runlogboek. Voor die bestanden geldt dat het uitblijven van een bevinding niets bewijst." \
        "file=$candidate" \
        "remediation=Bekijk de betreffende bestanden handmatig of draai de scan opnieuw als de oorzaak verholpen is."
    return 0
}

detect_regex_demotion_reason() {
    local site_path=$1 candidate=$2
    local base=${candidate##*/}
    local lower=${base,,}
    local relative=${candidate#"$site_path"/}
    case $candidate in
        */vendor/*|*/vendor_prefixed/*|*/node_modules/*|*/composer/*|*/guzzle/*|*/psr/*)
            printf 'het bestand staat in een bibliotheekmap van derden'
            return 0
            ;;
        */getid3/*|*/tinymce/*|*/tiny_mce/*|*/phpmailer/*|*/simplepie/*|*/htmlpurifier/*|*/phpseclib/*|*/swiftmailer/*|*/smarty/*|*/adodb/*|*/phpthumb/*|*/tcpdf/*|*/dompdf/*|*/fpdf/*|*/mpdf/*|*/phpexcel/*|*/phpspreadsheet/*)
            printf 'het bestand hoort bij een bibliotheek die van huis uit dingen doet die op verhulling lijken'
            return 0
            ;;
        */wp-content/wflogs/*)
            printf 'het bestand hoort bij de regelbestanden van een beveiligingsplugin'
            return 0
            ;;
    esac
    case $relative in
        wp-content/languages/*)
            printf 'het bestand hoort bij de vertaalbestanden van WordPress'
            return 0
            ;;
        wp-content/plugins/*secur*/*|wp-content/plugins/*scan*/*|wp-content/plugins/*firewall*/*|wp-content/plugins/*wordfence*/*|wp-content/plugins/*malware*/*|wp-content/plugins/*antivirus*/*|wp-content/plugins/*defender*/*|wp-content/plugins/*shield*/*|wp-content/plugins/*cerber*/*|wp-content/plugins/*sucuri*/*)
            printf 'het bestand hoort bij een beveiligingsplugin, en die bewaren de patronen waar wij op zoeken zelf ook als tekst'
            return 0
            ;;
    esac
    case $lower in
        *.log.php|error_log)
            printf 'het bestand is een logboek dat toevallig op php eindigt'
            return 0
            ;;
    esac
    if ! detect_regex_name_runs_as_php "$base"; then
        printf 'een bestand met deze extensie wordt niet als PHP uitgevoerd'
        return 0
    fi
    if is_allowlisted_path "$candidate"; then
        printf 'het pad staat op de allowlist in de configuratie'
        return 0
    fi
    return 1
}

detect_regex_signal_is_suppressed() {
    local category=$1 target=$2 status=0
    if [ "$category" != "hex-escape-run" ]; then
        return 1
    fi
    "${WP2SHELL_GREP:-grep}" -E -i -q \
        -e '\\x47\\x49\\x46\\x38\\x39\\x61|\\x89\\x50\\x4e\\x47|\\xff\\xd8\\xff|\\x25\\x50\\x44\\x46' \
        -- "$target" 2>/dev/null || status=$?
    if [ "$status" -eq 0 ]; then
        log_debug "Hex-reeks genegeerd, het bestand bevat een ingebedde afbeelding of pdf: $target"
        return 0
    fi
    return 1
}

detect_regex_prepare_prefix() {
    local candidate=$1 limit=$2
    if [ -z "$WP2SHELL_REGEX_PREFIX_FILE" ]; then
        WP2SHELL_REGEX_PREFIX_FILE=$(mktemp -t wp2shell-regex-prefix.XXXXXXXX) || return 1
        register_temp_cleanup "$WP2SHELL_REGEX_PREFIX_FILE"
    fi
    head -c "$limit" -- "$candidate" > "$WP2SHELL_REGEX_PREFIX_FILE" 2>/dev/null || return 1
    return 0
}

detect_regex_gate_matches() {
    local gate_file=$1 target=$2 status=0
    "${WP2SHELL_GREP:-grep}" "${WP2SHELL_REGEX_SPAN_ARGS[@]+"${WP2SHELL_REGEX_SPAN_ARGS[@]}"}" \
        -E -i -q -f "$gate_file" -- "$target" 2>/dev/null || status=$?
    printf '%s' "$status"
    return 0
}

detect_regex_reset_matches() {
    WP2SHELL_REGEX_MATCH_IDS=()
    WP2SHELL_REGEX_SUPPRESSED_COUNT=0
    return 0
}

detect_regex_collect_tier() {
    local target=$1 tier=$2
    local identifier status
    for identifier in "${WP2SHELL_REGEX_IDS[@]+"${WP2SHELL_REGEX_IDS[@]}"}"; do
        if [ "${WP2SHELL_REGEX_CONFIDENCE[$identifier]}" != "$tier" ]; then
            continue
        fi
        status=0
        "${WP2SHELL_GREP:-grep}" "${WP2SHELL_REGEX_SPAN_ARGS[@]+"${WP2SHELL_REGEX_SPAN_ARGS[@]}"}" \
            -E -i -q -e "${WP2SHELL_REGEX_EXPRESSION[$identifier]}" -- "$target" 2>/dev/null || status=$?
        if [ "$status" -gt 1 ]; then
            log_warn "Patrooncontrole is mislukt op $target bij ${WP2SHELL_REGEX_CATEGORY[$identifier]}"
            return 1
        fi
        if [ "$status" -ne 0 ]; then
            continue
        fi
        if detect_regex_signal_is_suppressed "${WP2SHELL_REGEX_CATEGORY[$identifier]}" "$target"; then
            WP2SHELL_REGEX_SUPPRESSED_COUNT=$((WP2SHELL_REGEX_SUPPRESSED_COUNT + 1))
            continue
        fi
        WP2SHELL_REGEX_MATCH_IDS+=("$identifier")
    done
    return 0
}

detect_regex_distinct_category_count() {
    local tier=$1
    local identifier category known seen_category total=0
    local -a seen=()
    for identifier in "${WP2SHELL_REGEX_MATCH_IDS[@]+"${WP2SHELL_REGEX_MATCH_IDS[@]}"}"; do
        if [ "${WP2SHELL_REGEX_CONFIDENCE[$identifier]}" != "$tier" ]; then
            continue
        fi
        category=${WP2SHELL_REGEX_CATEGORY[$identifier]}
        known=0
        for seen_category in "${seen[@]+"${seen[@]}"}"; do
            if [ "$seen_category" = "$category" ]; then
                known=1
            fi
        done
        if [ "$known" = "0" ]; then
            seen+=("$category")
            total=$((total + 1))
        fi
    done
    printf '%s' "$total"
    return 0
}

detect_regex_evidence_for() {
    local target=$1 identifier=$2 raw=''
    raw=$("${WP2SHELL_GREP:-grep}" "${WP2SHELL_REGEX_SPAN_ARGS[@]+"${WP2SHELL_REGEX_SPAN_ARGS[@]}"}" \
        -E -i -o -e "${WP2SHELL_REGEX_EXPRESSION[$identifier]}" -- "$target" 2>/dev/null |
        head -c "$WP2SHELL_REGEX_EVIDENCE_BYTES" | tr -d '\000') || raw=''
    detect_regex_evidence_snippet "$raw"
    return 0
}

detect_regex_file_sha1() {
    local value
    value=$(file_sha1 "$1") || value=''
    value=${value,,}
    value=${value#\\}
    if [ "${#value}" -ne 40 ]; then
        printf ''
        return 0
    fi
    printf '%s' "$value"
    return 0
}

detect_regex_join_labels() {
    local first=1 category
    for category in "$@"; do
        if [ "$first" = "1" ]; then
            first=0
        else
            printf ', '
        fi
        detect_regex_category_label "$category"
    done
    if [ "$first" = "1" ]; then
        printf 'geen'
    fi
    return 0
}

detect_regex_report_matches() {
    local site_path=$1 candidate=$2 target=$3 truncated=$4
    local -a high_categories=() medium_categories=() low_categories=()
    local identifier category confidence known known_category
    local conclusive=0 evidence_id='' medium_id='' low_id=''
    for identifier in "${WP2SHELL_REGEX_MATCH_IDS[@]+"${WP2SHELL_REGEX_MATCH_IDS[@]}"}"; do
        category=${WP2SHELL_REGEX_CATEGORY[$identifier]}
        confidence=${WP2SHELL_REGEX_CONFIDENCE[$identifier]}
        case $confidence in
            high)
                known=0
                for known_category in "${high_categories[@]+"${high_categories[@]}"}"; do
                    if [ "$known_category" = "$category" ]; then
                        known=1
                    fi
                done
                if [ "$known" = "0" ]; then
                    high_categories+=("$category")
                fi
                if [ -z "$evidence_id" ]; then
                    evidence_id="$identifier"
                fi
                if detect_regex_category_is_conclusive "$category"; then
                    conclusive=1
                    evidence_id="$identifier"
                fi
                ;;
            medium)
                known=0
                for known_category in "${medium_categories[@]+"${medium_categories[@]}"}"; do
                    if [ "$known_category" = "$category" ]; then
                        known=1
                    fi
                done
                if [ "$known" = "0" ]; then
                    medium_categories+=("$category")
                fi
                if [ -z "$medium_id" ]; then
                    medium_id="$identifier"
                fi
                ;;
            *)
                known=0
                for known_category in "${low_categories[@]+"${low_categories[@]}"}"; do
                    if [ "$known_category" = "$category" ]; then
                        known=1
                    fi
                done
                if [ "$known" = "0" ]; then
                    low_categories+=("$category")
                fi
                if [ -z "$low_id" ]; then
                    low_id="$identifier"
                fi
                ;;
        esac
    done
    local high_total=${#high_categories[@]}
    local medium_total=${#medium_categories[@]}
    local low_total=${#low_categories[@]}
    if [ "$high_total" -eq 0 ] && [ "$medium_total" -lt 2 ]; then
        log_debug "Regexlaag: te weinig signalen voor een bevinding in $candidate"
        return 0
    fi
    local demotion=''
    local demoted=0
    if demotion=$(detect_regex_demotion_reason "$site_path" "$candidate"); then
        demoted=1
    else
        demotion=''
    fi
    local severity confidence_level category_name title detail
    local strong_summary weak_summary context_summary
    strong_summary=$(detect_regex_join_labels "${high_categories[@]+"${high_categories[@]}"}")
    weak_summary=$(detect_regex_join_labels "${medium_categories[@]+"${medium_categories[@]}"}")
    context_summary=$(detect_regex_join_labels "${low_categories[@]+"${low_categories[@]}"}")
    if [ -z "$evidence_id" ]; then
        evidence_id="$medium_id"
    fi
    if [ -z "$evidence_id" ]; then
        evidence_id="$low_id"
    fi
    if [ "$high_total" -eq 0 ]; then
        severity="$SEVERITY_MEDIUM"
        confidence_level="$CONFIDENCE_HEURISTIC"
        category_name="regex-suspicious-code"
        title="Verdachte combinatie van patronen in PHP-bestand"
        detail="De regex-laag herkent $medium_total patronen die elk afzonderlijk ook in legitieme code voorkomen: $weak_summary. Geen daarvan is sterk genoeg voor een bevestiging, ook niet samen, dus dit is uitsluitend een aanwijzing voor handmatige review."
    elif [ "$conclusive" = "1" ] && [ "$demoted" = "0" ]; then
        severity="$SEVERITY_CRITICAL"
        confidence_level="$CONFIDENCE_HIGH"
        category_name="regex-backdoor-signature"
        title="Bevestigd backdoor-patroon in PHP-bestand"
        detail="Dit bestand voert invoer uit het verzoek rechtstreeks uit als PHP-code: $strong_summary. Daar bestaat geen legitieme toepassing voor, dus dit patroon geldt op zichzelf als bevestigd."
    elif [ "$high_total" -ge 2 ] && [ "$demoted" = "0" ]; then
        severity="$SEVERITY_CRITICAL"
        confidence_level="$CONFIDENCE_HIGH"
        category_name="regex-backdoor-signature"
        title="Bevestigd backdoor-patroon in PHP-bestand"
        detail="Er zijn $high_total onafhankelijke sterke patronen uit verschillende categorieen aangetroffen: $strong_summary. Een enkel sterk patroon blijft heuristisch, want ook betaalde plugins worden soms versleuteld uitgeleverd. Vanaf twee onafhankelijke categorieen wordt dit als bevestigd gerapporteerd."
    else
        severity="$SEVERITY_HIGH"
        confidence_level="$CONFIDENCE_HEURISTIC"
        category_name="regex-backdoor-signature"
        title="Sterk patroon in PHP-bestand, handmatige beoordeling nodig"
        if [ "$high_total" -ge 2 ]; then
            detail="Er zijn $high_total sterke patronen aangetroffen: $strong_summary."
        else
            detail="Er is een sterk patroon aangetroffen: $strong_summary. Een enkel sterk patroon blijft bewust heuristisch, want obfuscatie komt ook voor in legitieme betaalde plugins en themas."
        fi
    fi
    if [ "$medium_total" -gt 0 ] && [ "$high_total" -gt 0 ]; then
        detail="$detail Aanvullende zwakkere patronen: $weak_summary."
    fi
    if [ "$low_total" -gt 0 ]; then
        detail="$detail Alleen als context, nooit als grond voor een bevinding: $context_summary."
    fi
    if [ "$demoted" = "1" ]; then
        detail="$detail Deze bevinding is bewust naar heuristisch teruggezet omdat $demotion. Automatisch verplaatsen zou hier een legitiem bestand kunnen raken."
    fi
    if [ "$truncated" = "1" ]; then
        detail="$detail Let op: alleen het eerste deel van dit bestand is gelezen, de rest is niet gecontroleerd."
    fi
    record_finding \
        "site=$site_path" \
        "severity=$severity" \
        "confidence=$confidence_level" \
        "category=$category_name" \
        "title=$title" \
        "detail=$detail" \
        "file=$candidate" \
        "sha1=$(detect_regex_file_sha1 "$candidate")" \
        "evidence=$(detect_regex_evidence_for "$target" "$evidence_id")" \
        "remediation=Vergelijk dit bestand met de originele plugin, het originele thema of de WordPress-kern. Zet het pas in quarantaine als vaststaat dat het daar niet in thuishoort."
    return 0
}

detect_regex_scan_file() {
    local site_path=${1:-}
    local candidate=${2:-}
    local known_size=${3:-}
    if [ -z "$site_path" ] || [ -z "$candidate" ]; then
        log_error "detect_regex_scan_file is aangeroepen zonder sitepad of bestandspad"
        return "$EXIT_INTERNAL"
    fi
    site_path=${site_path%/}
    detect_regex_load_patterns_once || true
    detect_regex_report_pattern_gap "$site_path"
    if [ "$WP2SHELL_REGEX_LOAD_FAILED" = "1" ]; then
        return 1
    fi
    detect_regex_report_span_gap "$site_path"
    if [ -L "$candidate" ]; then
        log_debug "Symlink overgeslagen in de regex-laag: $candidate"
        return 0
    fi
    if [ ! -f "$candidate" ] || [ ! -r "$candidate" ]; then
        detect_regex_report_unscanned "$site_path" "$candidate" unreadable \
            "het bestand is geen gewoon bestand of niet leesbaar"
        return 1
    fi
    local base=${candidate##*/}
    if ! detect_regex_is_scannable_name "$base"; then
        log_debug "Buiten het bereik van de regex-laag, overgeslagen: $candidate"
        return 0
    fi
    local size=$known_size
    case $size in
        ''|*[!0-9]*)
            size=$(file_size_bytes "$candidate") || size=0
            ;;
    esac
    case $size in
        ''|*[!0-9]*) size=0 ;;
    esac
    if [ "$size" -eq 0 ]; then
        log_debug "Leeg bestand overgeslagen in de regex-laag: $candidate"
        return 0
    fi
    if ! "${WP2SHELL_GREP:-grep}" -I -q -m1 -e . -- "$candidate" 2>/dev/null; then
        detect_regex_report_unscanned "$site_path" "$candidate" binary \
            "het bestand bevat binaire data en tekstpatronen zijn er niet betrouwbaar op toe te passen"
        return 1
    fi
    local limit=${WP2SHELL_REGEX_MAX_FILE_BYTES:-${WP2SHELL_HEURISTIC_MAX_FILE_BYTES:-5242880}}
    local target=$candidate
    local truncated=0
    if [ "$size" -gt "$limit" ]; then
        if ! detect_regex_prepare_prefix "$candidate" "$limit"; then
            detect_regex_report_unscanned "$site_path" "$candidate" prefix \
                "het bestand is groter dan $limit bytes en het eerste deel kon niet apart weggeschreven worden"
            return 1
        fi
        target="$WP2SHELL_REGEX_PREFIX_FILE"
        truncated=1
        detect_regex_report_unscanned "$site_path" "$candidate" truncated \
            "het bestand is groter dan $limit bytes, alleen het eerste deel is gecontroleerd"
    fi
    local gate_status strong_status
    gate_status=$(detect_regex_gate_matches "$WP2SHELL_REGEX_GATE_FILE" "$target")
    if [ "$gate_status" -gt 1 ]; then
        detect_regex_report_unscanned "$site_path" "$candidate" gate \
            "de gecombineerde patrooncontrole gaf exitcode $gate_status"
        return 1
    fi
    if [ "$gate_status" -ne 0 ]; then
        return 0
    fi
    strong_status=$(detect_regex_gate_matches "$WP2SHELL_REGEX_STRONG_GATE_FILE" "$target")
    if [ "$strong_status" -gt 1 ]; then
        detect_regex_report_unscanned "$site_path" "$candidate" gate \
            "de patrooncontrole op de sterke patronen gaf exitcode $strong_status"
        return 1
    fi
    detect_regex_reset_matches
    if [ "$strong_status" -eq 0 ]; then
        if ! detect_regex_collect_tier "$target" high; then
            detect_regex_report_unscanned "$site_path" "$candidate" identify \
                "de sterke patronen konden na een treffer niet afzonderlijk gecontroleerd worden"
            return 1
        fi
    fi
    if ! detect_regex_collect_tier "$target" medium; then
        detect_regex_report_unscanned "$site_path" "$candidate" identify \
            "de zwakkere patronen konden na een treffer niet afzonderlijk gecontroleerd worden"
        return 1
    fi
    if [ "$strong_status" -ne 0 ] && [ "$(detect_regex_distinct_category_count medium)" -lt 2 ]; then
        log_debug "Regexlaag: te weinig signalen voor een bevinding in $candidate"
        return 0
    fi
    if ! detect_regex_collect_tier "$target" low; then
        detect_regex_report_unscanned "$site_path" "$candidate" identify \
            "de ondersteunende patronen konden na een treffer niet afzonderlijk gecontroleerd worden"
        return 1
    fi
    if [ "${#WP2SHELL_REGEX_MATCH_IDS[@]}" -eq 0 ]; then
        if [ "$WP2SHELL_REGEX_SUPPRESSED_COUNT" -eq 0 ]; then
            log_warn "De gecombineerde patrooncontrole sloeg aan op $candidate maar geen enkel patroon bevestigde dat"
        fi
        return 0
    fi
    detect_regex_report_matches "$site_path" "$candidate" "$target" "$truncated"
    return 0
}
