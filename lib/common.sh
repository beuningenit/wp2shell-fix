WP2SHELL_COMMON_LOADED=1

WP2SHELL_TEMP_PATHS=()
WP2SHELL_ALLOWLIST_PATHS=()
WP2SHELL_ALLOWLIST_ADMIN_LOGINS=()
WP2SHELL_ALLOWLIST_ADMIN_EMAILS=()
WP2SHELL_LOCK_FD=

EXIT_OK=0
EXIT_USAGE=1
EXIT_INTERNAL=2
EXIT_LOCKED=3
EXIT_FINDING_INFO=10
EXIT_FINDING_LOW=20
EXIT_FINDING_MEDIUM=30
EXIT_FINDING_HIGH=40
EXIT_FINDING_CRITICAL=50

SEVERITY_INFO=info
SEVERITY_LOW=low
SEVERITY_MEDIUM=medium
SEVERITY_HIGH=high
SEVERITY_CRITICAL=critical

CONFIDENCE_HIGH=high-confidence
CONFIDENCE_HEURISTIC=heuristic

severity_rank() {
    case $1 in
        "$SEVERITY_CRITICAL") printf '50' ;;
        "$SEVERITY_HIGH") printf '40' ;;
        "$SEVERITY_MEDIUM") printf '30' ;;
        "$SEVERITY_LOW") printf '20' ;;
        "$SEVERITY_INFO") printf '10' ;;
        *) printf '0' ;;
    esac
}

severity_from_rank() {
    case $1 in
        50) printf '%s' "$SEVERITY_CRITICAL" ;;
        40) printf '%s' "$SEVERITY_HIGH" ;;
        30) printf '%s' "$SEVERITY_MEDIUM" ;;
        20) printf '%s' "$SEVERITY_LOW" ;;
        10) printf '%s' "$SEVERITY_INFO" ;;
        *) printf 'none' ;;
    esac
}

severity_exit_code() {
    case $1 in
        "$SEVERITY_CRITICAL") printf '%s' "$EXIT_FINDING_CRITICAL" ;;
        "$SEVERITY_HIGH") printf '%s' "$EXIT_FINDING_HIGH" ;;
        "$SEVERITY_MEDIUM") printf '%s' "$EXIT_FINDING_MEDIUM" ;;
        "$SEVERITY_LOW") printf '%s' "$EXIT_FINDING_LOW" ;;
        "$SEVERITY_INFO") printf '%s' "$EXIT_FINDING_INFO" ;;
        *) printf '%s' "$EXIT_OK" ;;
    esac
}

severity_dutch_label() {
    case $1 in
        "$SEVERITY_CRITICAL") printf 'kritiek' ;;
        "$SEVERITY_HIGH") printf 'hoog' ;;
        "$SEVERITY_MEDIUM") printf 'middel' ;;
        "$SEVERITY_LOW") printf 'laag' ;;
        "$SEVERITY_INFO") printf 'informatief' ;;
        *) printf 'onbekend' ;;
    esac
}

confidence_dutch_label() {
    case $1 in
        "$CONFIDENCE_HIGH") printf 'bevestigd' ;;
        "$CONFIDENCE_HEURISTIC") printf 'heuristisch, handmatige review nodig' ;;
        *) printf 'onbekend' ;;
    esac
}

timestamp_iso() {
    date -u '+%Y-%m-%dT%H:%M:%SZ'
}

timestamp_compact() {
    date -u '+%Y%m%d-%H%M%S'
}

timestamp_dutch() {
    date '+%d-%m-%Y %H:%M:%S %Z'
}

log_write() {
    local level=$1
    shift
    local line
    line="$(timestamp_iso) [$level] $*"
    if [ -n "${WP2SHELL_RUN_LOG:-}" ]; then
        printf '%s\n' "$line" >>"$WP2SHELL_RUN_LOG" 2>/dev/null || true
    fi
    if [ "$level" = "DEBUG" ]; then
        if [ "${WP2SHELL_VERBOSE:-0}" = "1" ]; then
            printf '%s\n' "$line" >&2
        fi
    else
        printf '%s\n' "$line" >&2
    fi
    return 0
}

log_debug() { log_write DEBUG "$@"; }
log_info() { log_write INFO "$@"; }
log_warn() { log_write WARN "$@"; }
log_error() { log_write ERROR "$@"; }

die() {
    local code=$1
    shift
    log_error "$@"
    exit "$code"
}

audit_write() {
    if [ -n "${WP2SHELL_AUDIT_LOG:-}" ]; then
        printf '%s %s\n' "$(timestamp_iso)" "$*" >>"$WP2SHELL_AUDIT_LOG" 2>/dev/null || true
    fi
    log_debug "audit: $*"
    return 0
}

have_command() {
    command -v "$1" >/dev/null 2>&1
}

require_command() {
    local missing=0
    local cmd
    for cmd in "$@"; do
        if ! have_command "$cmd"; then
            log_error "Vereist commando ontbreekt: $cmd"
            missing=1
        fi
    done
    return "$missing"
}

detect_optional_commands() {
    WP2SHELL_HAS_JQ=0
    WP2SHELL_HAS_NICE=0
    WP2SHELL_HAS_IONICE=0
    WP2SHELL_HAS_CLAMSCAN=0
    WP2SHELL_HAS_CLAMDSCAN=0
    WP2SHELL_HAS_ICONV=0
    WP2SHELL_HAS_TIMEOUT=0
    WP2SHELL_HAS_FLOCK=0
    WP2SHELL_HAS_SUDO=0
    if have_command jq; then WP2SHELL_HAS_JQ=1; fi
    if have_command nice; then WP2SHELL_HAS_NICE=1; fi
    if have_command ionice; then WP2SHELL_HAS_IONICE=1; fi
    if have_command clamscan; then WP2SHELL_HAS_CLAMSCAN=1; fi
    if have_command clamdscan; then WP2SHELL_HAS_CLAMDSCAN=1; fi
    if have_command iconv; then WP2SHELL_HAS_ICONV=1; fi
    if have_command timeout; then WP2SHELL_HAS_TIMEOUT=1; fi
    if have_command flock; then WP2SHELL_HAS_FLOCK=1; fi
    if have_command sudo; then WP2SHELL_HAS_SUDO=1; fi
    return 0
}

resolve_tool_path() {
    local name=$1
    shift
    local candidate
    for candidate in "$@"; do
        if [ -x "$candidate" ]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    candidate=$(command -v "$name" 2>/dev/null) || candidate=''
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then
        printf '%s' "$candidate"
        return 0
    fi
    return 1
}

tool_is_gnu() {
    local binary=$1 marker=$2
    "$binary" --version 2>/dev/null | head -1 | grep -q "$marker"
}

resolve_external_tools() {
    umask 077
    PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    export PATH
    WP2SHELL_FIND=$(resolve_tool_path find /usr/bin/find /bin/find) || return 1
    WP2SHELL_GREP=$(resolve_tool_path grep /usr/bin/grep /bin/grep) || return 1
    WP2SHELL_TAR=$(resolve_tool_path tar /usr/bin/tar /bin/tar) || return 1
    WP2SHELL_SORT=$(resolve_tool_path sort /usr/bin/sort /bin/sort) || return 1
    local strict=${WP2SHELL_REQUIRE_GNU_TOOLS:-1}
    local failures=0
    if ! tool_is_gnu "$WP2SHELL_FIND" 'GNU findutils'; then
        log_warn "$WP2SHELL_FIND is geen GNU findutils, de symlink-semantiek kan afwijken"
        failures=$((failures + 1))
    fi
    if ! tool_is_gnu "$WP2SHELL_GREP" 'GNU grep'; then
        log_warn "$WP2SHELL_GREP is geen GNU grep, het zoekgedrag kan afwijken"
        failures=$((failures + 1))
    fi
    if [ "$failures" -gt 0 ] && [ "$strict" = "1" ]; then
        log_error "Deze toolkit vereist GNU find en GNU grep, want de veiligheidsgaranties rond symlinks hangen daarvan af"
        log_error "Zet WP2SHELL_REQUIRE_GNU_TOOLS=0 in de configuratie om dit bewust te negeren"
        return 1
    fi
    log_debug "Tools: find=$WP2SHELL_FIND grep=$WP2SHELL_GREP tar=$WP2SHELL_TAR"
    return 0
}

sanitize_text() {
    local cleaned
    cleaned=$(printf '%s.' "$1" | LC_ALL=C tr -d '\000-\010\013\014\016-\037\177')
    cleaned=${cleaned%.}
    if [ "${WP2SHELL_HAS_ICONV:-0}" = "1" ]; then
        local converted
        converted=$(printf '%s.' "$cleaned" | iconv -f UTF-8 -t UTF-8 -c 2>/dev/null) || true
        if [ -n "$converted" ]; then
            cleaned=${converted%.}
        fi
    fi
    printf '%s' "$cleaned"
}

json_escape_string() {
    local raw
    raw=$(sanitize_text "$1")
    raw=${raw//\\/\\\\}
    raw=${raw//\"/\\\"}
    raw=${raw//$'\n'/\\n}
    raw=${raw//$'\r'/\\r}
    raw=${raw//$'\t'/\\t}
    printf '%s' "$raw"
}

json_string() {
    printf '"%s"' "$(json_escape_string "$1")"
}

path_to_base64() {
    printf '%s' "$1" | base64 -w0 2>/dev/null || printf '%s' "$1" | base64 | tr -d '\n'
}

path_is_json_lossy() {
    local original=$1 roundtrip
    roundtrip=$(sanitize_text "$original")
    [ "$roundtrip" != "$original" ]
}

json_number_or_null() {
    case $1 in
        '') printf 'null' ;;
        *[!0-9]*) printf 'null' ;;
        *) printf '%s' "$1" ;;
    esac
}

json_bool() {
    if [ "$1" = "1" ] || [ "$1" = "true" ] || [ "$1" = "yes" ]; then
        printf 'true'
    else
        printf 'false'
    fi
}

json_extract_field() {
    local record=$1 field=$2
    local pattern="\"$field\":"
    local remainder=${record#*"$pattern"}
    if [ "$remainder" = "$record" ]; then
        return 1
    fi
    case $remainder in
        '"'*)
            remainder=${remainder#\"}
            local out='' ch next
            while [ -n "$remainder" ]; do
                ch=${remainder:0:1}
                if [ "$ch" = $'\\' ]; then
                    next=${remainder:1:1}
                    case $next in
                        n) out+=$'\n' ;;
                        r) out+=$'\r' ;;
                        t) out+=$'\t' ;;
                        '"') out+='"' ;;
                        \\) out+=$'\\' ;;
                        *) out+="$next" ;;
                    esac
                    remainder=${remainder:2}
                elif [ "$ch" = '"' ]; then
                    break
                else
                    out+="$ch"
                    remainder=${remainder:1}
                fi
            done
            printf '%s' "$out"
            return 0
            ;;
        *)
            local value=${remainder%%,*}
            value=${value%\}}
            value=${value%\}*}
            printf '%s' "$value"
            return 0
            ;;
    esac
}

path_is_lexically_within() {
    local candidate=$1 base=$2
    case $candidate in
        /*) ;;
        *) return 1 ;;
    esac
    case $candidate in
        *"/../"*|*/..) return 1 ;;
    esac
    base=${base%/}
    case $candidate in
        "$base"/*) return 0 ;;
    esac
    return 1
}

path_is_within() {
    local resolved_candidate resolved_parent
    if ! resolved_candidate=$(readlink -f -- "$1" 2>/dev/null); then
        return 1
    fi
    if ! resolved_parent=$(readlink -f -- "$2" 2>/dev/null); then
        return 1
    fi
    if [ -z "$resolved_candidate" ] || [ -z "$resolved_parent" ]; then
        return 1
    fi
    case $resolved_candidate in
        "$resolved_parent") return 0 ;;
        "$resolved_parent"/*) return 0 ;;
        *) return 1 ;;
    esac
}

path_has_no_symlink() {
    local resolved
    if ! resolved=$(readlink -f -- "$1" 2>/dev/null); then
        return 1
    fi
    [ "$resolved" = "$1" ]
}

make_temp_dir() {
    local template=${1:-wp2shell}
    mktemp -d -t "${template}.XXXXXXXXXX"
}

register_temp_cleanup() {
    WP2SHELL_TEMP_PATHS+=("$1")
    return 0
}

cleanup_temp_paths() {
    local path
    if [ "${#WP2SHELL_TEMP_PATHS[@]}" -eq 0 ]; then
        return 0
    fi
    for path in "${WP2SHELL_TEMP_PATHS[@]}"; do
        if [ -n "$path" ] && [ -e "$path" ]; then
            case $path in
                /tmp/*|/var/tmp/*) rm -rf -- "$path" 2>/dev/null || true ;;
            esac
        fi
    done
    WP2SHELL_TEMP_PATHS=()
    return 0
}

install_cleanup_trap() {
    trap 'cleanup_temp_paths' EXIT
    trap 'cleanup_temp_paths; exit 130' INT
    trap 'cleanup_temp_paths; exit 143' TERM
    return 0
}

WP2SHELL_LOCK_MARKER="wp2shell-lock"

lock_path_is_acceptable() {
    local lock_path=$1 size first=''
    if [ -L "$lock_path" ]; then
        log_error "Het lockbestand is een symlink en wordt niet gevolgd: $lock_path"
        return 1
    fi
    if [ -d "$lock_path" ]; then
        log_error "Het lockbestand is een map: $lock_path"
        return 1
    fi
    if [ ! -e "$lock_path" ]; then
        return 0
    fi
    if [ ! -f "$lock_path" ]; then
        log_error "Het lockbestand is geen gewoon bestand: $lock_path"
        return 1
    fi
    size=$(stat -c '%s' -- "$lock_path" 2>/dev/null) || size=0
    case $size in
        ''|*[!0-9]*) size=0 ;;
    esac
    if [ "$size" -eq 0 ]; then
        return 0
    fi
    read -r first < "$lock_path" 2>/dev/null || first=''
    if [ "$first" = "$WP2SHELL_LOCK_MARKER" ]; then
        return 0
    fi
    log_error "Het opgegeven bestand is geen lockbestand van wp2shell en wordt niet aangeraakt: $lock_path"
    return 1
}

acquire_run_lock() {
    local lock_path=$1
    mkdir -p -- "$(dirname -- "$lock_path")" 2>/dev/null || true
    if ! lock_path_is_acceptable "$lock_path"; then
        return 1
    fi
    if [ "${WP2SHELL_HAS_FLOCK:-0}" != "1" ]; then
        log_warn "flock ontbreekt, gelijktijdige uitvoering wordt niet afgedwongen"
        return 0
    fi
    if ! exec {WP2SHELL_LOCK_FD}>>"$lock_path"; then
        log_error "Kan lockbestand niet openen: $lock_path"
        return 1
    fi
    if ! flock -n "$WP2SHELL_LOCK_FD"; then
        return 1
    fi
    if lock_path_is_acceptable "$lock_path"; then
        printf '%s\n%s\n' "$WP2SHELL_LOCK_MARKER" "$$" > "$lock_path" 2>/dev/null || true
    fi
    return 0
}

release_run_lock() {
    if [ -n "${WP2SHELL_LOCK_FD:-}" ]; then
        flock -u "$WP2SHELL_LOCK_FD" 2>/dev/null || true
        exec {WP2SHELL_LOCK_FD}>&- 2>/dev/null || true
        WP2SHELL_LOCK_FD=
    fi
    return 0
}

current_user_name() {
    id -un
}

user_exists() {
    id -u "$1" >/dev/null 2>&1
}

user_home_dir() {
    local home
    home=$(getent passwd "$1" 2>/dev/null | cut -d: -f6)
    if [ -z "$home" ]; then
        home="/home/$1"
    fi
    printf '%s' "$home"
}

path_owner() {
    stat -c '%U' -- "$1" 2>/dev/null
}

path_group() {
    stat -c '%G' -- "$1" 2>/dev/null
}

build_load_prefix() {
    WP2SHELL_LOAD_PREFIX=()
    if [ "${WP2SHELL_HAS_NICE:-0}" = "1" ]; then
        WP2SHELL_LOAD_PREFIX+=(nice -n "${WP2SHELL_NICE_LEVEL:-10}")
    fi
    if [ "${WP2SHELL_HAS_IONICE:-0}" = "1" ]; then
        WP2SHELL_LOAD_PREFIX+=(ionice -c "${WP2SHELL_IONICE_CLASS:-3}")
    fi
    return 0
}

run_as_user() {
    local user=$1
    shift
    if [ "$#" -eq 0 ]; then
        return "$EXIT_INTERNAL"
    fi
    local -a load_prefix=()
    if [ "${WP2SHELL_HAS_NICE:-0}" = "1" ]; then
        load_prefix+=(nice -n "${WP2SHELL_NICE_LEVEL:-10}")
    fi
    if [ "${WP2SHELL_HAS_IONICE:-0}" = "1" ]; then
        load_prefix+=(ionice -c "${WP2SHELL_IONICE_CLASS:-3}")
    fi
    local -a timeout_prefix=()
    if [ "${WP2SHELL_HAS_TIMEOUT:-0}" = "1" ] && [ -n "${WP2SHELL_COMMAND_TIMEOUT:-}" ]; then
        timeout_prefix=(timeout -k 10 "$WP2SHELL_COMMAND_TIMEOUT")
    fi
    if [ "$(current_user_name)" = "$user" ]; then
        "${timeout_prefix[@]}" "${load_prefix[@]}" "$@"
        return $?
    fi
    if [ "${WP2SHELL_HAS_SUDO:-0}" != "1" ]; then
        log_error "sudo ontbreekt, kan niet als gebruiker $user draaien"
        return "$EXIT_INTERNAL"
    fi
    local home
    home=$(user_home_dir "$user")
    "${timeout_prefix[@]}" sudo -n -u "$user" \
        env \
            HOME="$home" \
            USER="$user" \
            LOGNAME="$user" \
            SHELL=/bin/bash \
            PATH="/usr/local/bin:/usr/bin:/bin" \
            LC_ALL=C.UTF-8 \
            WP_CLI_CACHE_DIR="$home/.wp-cli/cache" \
            WP_CLI_DISABLE_AUTO_CHECK_UPDATE=1 \
        "${load_prefix[@]}" "$@"
}

wp_cli_binary() {
    if [ -n "${WP2SHELL_WP_CLI_PATH:-}" ] && [ -r "$WP2SHELL_WP_CLI_PATH" ]; then
        printf '%s' "$WP2SHELL_WP_CLI_PATH"
        return 0
    fi
    if have_command wp; then
        command -v wp
        return 0
    fi
    return 1
}

ensure_wp_cli() {
    local resolved
    if resolved=$(wp_cli_binary); then
        WP2SHELL_WP_CLI_RESOLVED="$resolved"
        return 0
    fi
    local target=${WP2SHELL_WP_CLI_PATH:-}
    if [ -z "$target" ]; then
        target="${WP2SHELL_STATE_DIR:-/var/lib/wp2shell}/wp-cli.phar"
    fi
    mkdir -p -- "$(dirname -- "$target")" 2>/dev/null || true
    log_info "WP-CLI ontbreekt, ophalen naar $target"
    if ! curl -fsSL --retry 3 --max-time 180 \
        https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar \
        -o "$target.download"; then
        log_error "Ophalen van WP-CLI is mislukt"
        return 1
    fi
    if ! php "$target.download" --info >/dev/null 2>&1; then
        log_error "Opgehaalde WP-CLI is niet bruikbaar"
        rm -f -- "$target.download"
        return 1
    fi
    mv -f -- "$target.download" "$target"
    chmod 0755 -- "$target"
    WP2SHELL_WP_CLI_PATH="$target"
    WP2SHELL_WP_CLI_RESOLVED="$target"
    return 0
}

wp_invoke() {
    local user=$1
    local site_path=$2
    local skip_extensions=$3
    shift 3
    local binary=${WP2SHELL_WP_CLI_RESOLVED:-}
    if [ -z "$binary" ]; then
        log_error "WP-CLI is niet beschikbaar"
        return "$EXIT_INTERNAL"
    fi
    local -a extra=()
    if [ "$skip_extensions" = "1" ]; then
        extra=(--skip-plugins --skip-themes)
    fi
    case $binary in
        *.phar)
            run_as_user "$user" php "$binary" --path="$site_path" --no-color "${extra[@]}" "$@"
            ;;
        *)
            run_as_user "$user" "$binary" --path="$site_path" --no-color "${extra[@]}" "$@"
            ;;
    esac
}

wp_run() {
    local user=$1
    local site_path=$2
    shift 2
    wp_invoke "$user" "$site_path" 1 "$@"
}

wp_run_with_extensions() {
    local user=$1
    local site_path=$2
    shift 2
    wp_invoke "$user" "$site_path" 0 "$@"
}

wp_is_functional() {
    local user=$1 site_path=$2 capture=${3:-}
    if [ -z "$capture" ]; then
        wp_run "$user" "$site_path" core is-installed >/dev/null 2>&1
        return $?
    fi
    local limit=${WP2SHELL_PROBE_CAPTURE_MAX_BYTES:-65536}
    case $limit in
        ''|*[!0-9]*) limit=65536 ;;
    esac
    : > "$capture" 2>/dev/null || true
    local -a probe_statuses=()
    wp_run "$user" "$site_path" core is-installed 2>&1 \
        | head -c "$limit" > "$capture"
    probe_statuses=("${PIPESTATUS[@]}")
    return "${probe_statuses[0]}"
}

wp_probe_failure_reason() {
    local capture=$1 status=$2 line reason='' limit captured=0
    limit=${WP2SHELL_PROBE_CAPTURE_MAX_BYTES:-65536}
    case $limit in
        ''|*[!0-9]*) limit=65536 ;;
    esac
    if [ -n "$capture" ] && [ -r "$capture" ]; then
        captured=$(stat -c '%s' -- "$capture" 2>/dev/null) || captured=0
        case $captured in
            ''|*[!0-9]*) captured=0 ;;
        esac
    fi
    if [ "$captured" -ge "$limit" ]; then
        printf 'wp core is-installed bleef uitvoer produceren en is afgekapt op %s bytes, dat wijst op een installatie die tijdens het opstarten blijft schrijven' "$limit"
        return 0
    fi
    if [ -n "$capture" ] && [ -s "$capture" ]; then
        while IFS= read -r line || [ -n "$line" ]; do
            case $line in
                ''|'PHP Warning:'*|'PHP Notice:'*|'PHP Deprecated:'*) continue ;;
            esac
            reason=$line
            break
        done < "$capture"
    fi
    if [ -z "$reason" ]; then
        case $status in
            13|141) reason="wp core is-installed werd afgebroken omdat de uitvoer niet meer gelezen werd" ;;
            124|137) reason="wp core is-installed liep in de tijdslimiet en is afgebroken" ;;
            126) reason="wp core is-installed mocht niet uitgevoerd worden, controleer sudo en de rechten op het WP-CLI-bestand" ;;
            127) reason="wp core is-installed vond php of WP-CLI niet in het pad /usr/local/bin:/usr/bin:/bin" ;;
            1) reason="wp core is-installed meldde geen werkende WordPress-installatie, zonder foutregel" ;;
            *) reason="wp core is-installed stopte met exitcode $status zonder uitvoer" ;;
        esac
    fi
    printf '%s' "${reason:0:400}"
    return 0
}

file_sha1() {
    sha1sum -- "$1" 2>/dev/null | cut -d' ' -f1
}

file_sha256() {
    sha256sum -- "$1" 2>/dev/null | cut -d' ' -f1
}

file_size_bytes() {
    stat -c '%s' -- "$1" 2>/dev/null
}

file_mtime_iso() {
    local epoch
    epoch=$(stat -c '%Y' -- "$1" 2>/dev/null) || epoch=0
    date -u -d "@$epoch" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null
}

site_identifier() {
    printf '%s' "$1" | sha1sum | cut -c1-12
}

record_finding() {
    local site_path='' site_id='' severity="$SEVERITY_INFO" confidence="$CONFIDENCE_HEURISTIC"
    local category='unknown' title='' detail='' file_path='' sha1='' evidence=''
    local action='reported' remediation=''
    local pair key value
    for pair in "$@"; do
        key=${pair%%=*}
        value=${pair#*=}
        case $key in
            site) site_path=$value ;;
            severity) severity=$value ;;
            confidence) confidence=$value ;;
            category) category=$value ;;
            title) title=$value ;;
            detail) detail=$value ;;
            file) file_path=$value ;;
            sha1) sha1=$value ;;
            evidence) evidence=$value ;;
            action) action=$value ;;
            remediation) remediation=$value ;;
        esac
    done
    if [ -n "$site_path" ]; then
        site_id=$(site_identifier "$site_path")
    fi
    if [ -z "${WP2SHELL_FINDINGS_FILE:-}" ]; then
        log_error "Geen findings-bestand ingesteld, bevinding gaat verloren: $title"
        return "$EXIT_INTERNAL"
    fi
    {
        printf '{'
        printf '"timestamp":%s,' "$(json_string "$(timestamp_iso)")"
        printf '"run_id":%s,' "$(json_string "${WP2SHELL_RUN_ID:-unknown}")"
        printf '"site_id":%s,' "$(json_string "$site_id")"
        printf '"site_path":%s,' "$(json_string "$site_path")"
        printf '"severity":%s,' "$(json_string "$severity")"
        printf '"severity_rank":%s,' "$(severity_rank "$severity")"
        printf '"confidence":%s,' "$(json_string "$confidence")"
        printf '"category":%s,' "$(json_string "$category")"
        printf '"title":%s,' "$(json_string "$title")"
        printf '"detail":%s,' "$(json_string "$detail")"
        printf '"file_path":%s,' "$(json_string "$file_path")"
        printf '"file_path_b64":%s,' "$(json_string "$(path_to_base64 "$file_path")")"
        printf '"file_path_lossy":%s,' "$(json_bool "$(path_is_json_lossy "$file_path" && printf '1' || printf '0')")"
        printf '"sha1":%s,' "$(json_string "$sha1")"
        printf '"evidence":%s,' "$(json_string "$evidence")"
        printf '"remediation":%s,' "$(json_string "$remediation")"
        printf '"action":%s' "$(json_string "$action")"
        printf '}\n'
    } >>"$WP2SHELL_FINDINGS_FILE"
    log_debug "bevinding [$severity/$confidence] $category: $title ($site_path)"
    return 0
}

worst_severity_from_findings() {
    local findings_file=${1:-${WP2SHELL_FINDINGS_FILE:-}}
    if [ -z "$findings_file" ] || [ ! -s "$findings_file" ]; then
        printf 'none'
        return 0
    fi
    local best=0 rank
    while IFS= read -r rank; do
        case $rank in
            ''|*[!0-9]*) continue ;;
        esac
        if [ "$rank" -gt "$best" ]; then
            best=$rank
        fi
    done < <(grep -o '"severity_rank":[0-9]*' "$findings_file" 2>/dev/null | cut -d: -f2)
    severity_from_rank "$best"
}

is_allowlisted_path() {
    local candidate=$1 entry
    if [ "${#WP2SHELL_ALLOWLIST_PATHS[@]}" -eq 0 ]; then
        return 1
    fi
    for entry in "${WP2SHELL_ALLOWLIST_PATHS[@]}"; do
        if [ -n "$entry" ]; then
            case $candidate in
                $entry) return 0 ;;
            esac
        fi
    done
    return 1
}

is_allowlisted_admin() {
    local login=$1 email=$2 entry
    if [ "${#WP2SHELL_ALLOWLIST_ADMIN_LOGINS[@]}" -gt 0 ]; then
        for entry in "${WP2SHELL_ALLOWLIST_ADMIN_LOGINS[@]}"; do
            if [ -n "$entry" ] && [ "$entry" = "$login" ]; then
                return 0
            fi
        done
    fi
    if [ "${#WP2SHELL_ALLOWLIST_ADMIN_EMAILS[@]}" -gt 0 ]; then
        for entry in "${WP2SHELL_ALLOWLIST_ADMIN_EMAILS[@]}"; do
            if [ -n "$entry" ]; then
                case $email in
                    $entry) return 0 ;;
                esac
            fi
        done
    fi
    return 1
}

load_configuration() {
    local config_path=$1
    if [ ! -f "$config_path" ]; then
        log_warn "Configuratiebestand niet gevonden: $config_path, standaardwaarden worden gebruikt"
        return 0
    fi
    local perms
    perms=$(stat -c '%a' -- "$config_path" 2>/dev/null) || perms=''
    case $perms in
        *[2367]) log_warn "Configuratiebestand $config_path is schrijfbaar voor anderen" ;;
    esac
    . "$config_path"
    return 0
}

send_report_mail() {
    local recipient=$1 subject=$2 body_file=$3 attachment=${4:-}
    if [ -z "$recipient" ]; then
        log_info "Geen ontvanger ingesteld, e-mail wordt overgeslagen"
        return 0
    fi
    if [ ! -f "$body_file" ]; then
        log_error "Rapporttekst ontbreekt: $body_file"
        return 1
    fi
    local sender=${WP2SHELL_MAIL_FROM:-}
    if [ -z "$sender" ]; then
        sender="wp2shell@$(hostname -f 2>/dev/null || hostname)"
    fi
    local mail_dir message boundary
    mail_dir=$(make_temp_dir wp2shell-mail)
    register_temp_cleanup "$mail_dir"
    message="$mail_dir/message.txt"
    boundary="wp2shell-$(timestamp_compact)-$$"
    {
        printf 'From: %s\n' "$sender"
        printf 'To: %s\n' "$recipient"
        printf 'Subject: %s\n' "$subject"
        printf 'MIME-Version: 1.0\n'
        if [ -n "$attachment" ] && [ -f "$attachment" ]; then
            printf 'Content-Type: multipart/mixed; boundary="%s"\n\n' "$boundary"
            printf -- '--%s\n' "$boundary"
            printf 'Content-Type: text/plain; charset="UTF-8"\n'
            printf 'Content-Transfer-Encoding: 8bit\n\n'
            cat -- "$body_file"
            printf '\n'
            printf -- '--%s\n' "$boundary"
            printf 'Content-Type: application/json; charset="UTF-8"\n'
            printf 'Content-Transfer-Encoding: base64\n'
            printf 'Content-Disposition: attachment; filename="%s"\n\n' "$(basename -- "$attachment")"
            base64 -- "$attachment"
            printf '\n'
            printf -- '--%s--\n' "$boundary"
        else
            printf 'Content-Type: text/plain; charset="UTF-8"\n'
            printf 'Content-Transfer-Encoding: 8bit\n\n'
            cat -- "$body_file"
        fi
    } >"$message"
    if have_command sendmail; then
        if sendmail -t <"$message"; then
            log_info "Rapport gemaild naar $recipient"
            return 0
        fi
    elif have_command msmtp; then
        if msmtp -t <"$message"; then
            log_info "Rapport gemaild naar $recipient"
            return 0
        fi
    elif have_command mail; then
        if mail -s "$subject" "$recipient" <"$body_file"; then
            log_info "Rapport gemaild naar $recipient"
            return 0
        fi
    elif have_command mailx; then
        if mailx -s "$subject" "$recipient" <"$body_file"; then
            log_info "Rapport gemaild naar $recipient"
            return 0
        fi
    fi
    log_error "Kon geen e-mail versturen naar $recipient, geen werkend mailcommando gevonden"
    return 1
}
