WP2SHELL_REFERENCE_LOADED=1

REFERENCE_STATUS_OBTAINED="obtained"
REFERENCE_STATUS_NOT_IN_DIRECTORY="not-in-directory"
REFERENCE_STATUS_LOOKUP_FAILED="lookup-failed"
REFERENCE_STATUS_CAP_REACHED="fetch-cap-reached"
REFERENCE_STATUS_OFFLINE_MISS="offline-miss"
REFERENCE_STATUS_UNSUPPORTED="unsupported-input"
REFERENCE_STATUS_ENGINE_UNAVAILABLE="engine-unavailable"
REFERENCE_STATUS_UNSAFE_PACKAGE="unsafe-package"
REFERENCE_STATUS_CHECKSUMS_ONLY="core-checksums-only"
REFERENCE_STATUS_UNKNOWN="unknown"

WP2SHELL_REFERENCE_LAST_STATUS="$REFERENCE_STATUS_UNKNOWN"
WP2SHELL_REFERENCE_LAST_DETAIL=""
WP2SHELL_REFERENCE_LAST_WARNING=""
WP2SHELL_REFERENCE_LAST_SOURCE=""
WP2SHELL_REFERENCE_LAST_MANIFEST=""
WP2SHELL_REFERENCE_LAST_MD5_MANIFEST=""
WP2SHELL_REFERENCE_LAST_CLOSED=0
WP2SHELL_REFERENCE_LAST_ENTRY_COUNT=0

WP2SHELL_REFERENCE_FETCH_COUNT=0
WP2SHELL_REFERENCE_CAP_REACHED=0
WP2SHELL_REFERENCE_ENGINE_CHECKED=0
WP2SHELL_REFERENCE_ENGINE_OK=0
WP2SHELL_REFERENCE_ENGINE_REASON=""
WP2SHELL_REFERENCE_EXTRACTOR=none
WP2SHELL_REFERENCE_JSON_TOOL=none
WP2SHELL_REFERENCE_SHA256_TOOL=none
WP2SHELL_REFERENCE_HTTP_OUTCOME=""
WP2SHELL_REFERENCE_HTTP_CODE=""
WP2SHELL_REFERENCE_HTTP_RC=0
WP2SHELL_REFERENCE_DOWNLOAD_OUTCOME=""
WP2SHELL_REFERENCE_CURL_ARGS=()

WP2SHELL_REFERENCE_INFO_PRESENT=0
WP2SHELL_REFERENCE_INFO_ERROR=""
WP2SHELL_REFERENCE_INFO_CLOSED=0
WP2SHELL_REFERENCE_INFO_SLUG=""
WP2SHELL_REFERENCE_INFO_VERSION=""
WP2SHELL_REFERENCE_INFO_VERSIONS_PRESENT=0
WP2SHELL_REFERENCE_INFO_VERSION_KNOWN=0
WP2SHELL_REFERENCE_INFO_VERSION_URL=""
WP2SHELL_REFERENCE_INFO_DOWNLOAD_LINK=""
WP2SHELL_REFERENCE_INFO_TEMPLATE=""

declare -gA WP2SHELL_REFERENCE_MEMO_STATUS=()
declare -gA WP2SHELL_REFERENCE_MEMO_MANIFEST=()
declare -gA WP2SHELL_REFERENCE_MEMO_DETAIL=()
declare -gA WP2SHELL_REFERENCE_MEMO_WARNING=()

reference_user_agent() {
    printf '%s' "${WP2SHELL_REFERENCE_USER_AGENT:-wp2shell-remediation/1.0 (defensive incident response toolkit)}"
    return 0
}

reference_cache_root() {
    printf '%s/reference' "${WP2SHELL_STATE_DIR:-/var/lib/wp2shell}"
    return 0
}

reference_cache_packages_dir() {
    printf '%s/packages' "$(reference_cache_root)"
    return 0
}

reference_cache_work_dir() {
    printf '%s/work' "$(reference_cache_root)"
    return 0
}

reference_single_line() {
    local raw=$1
    raw=${raw//$'\n'/ }
    raw=${raw//$'\r'/ }
    printf '%s' "$raw"
    return 0
}

reference_result_file() {
    if [ -n "${WP2SHELL_REFERENCE_RESULT_FILE:-}" ]; then
        printf '%s' "$WP2SHELL_REFERENCE_RESULT_FILE"
        return 0
    fi
    local root
    root=$(reference_cache_root)
    if mkdir -p -- "$root/run" 2>/dev/null && [ -w "$root/run" ]; then
        printf '%s/run/last-result.%s' "$root" "$$"
        return 0
    fi
    printf '%s/wp2shell-reference-result.%s' "${TMPDIR:-/tmp}" "$$"
    return 0
}

reference_load_run_state() {
    local file line key value
    file=$(reference_result_file)
    if [ ! -f "$file" ]; then
        return 1
    fi
    while IFS= read -r line || [ -n "$line" ]; do
        key=${line%%=*}
        value=${line#*=}
        case $key in
            status) WP2SHELL_REFERENCE_LAST_STATUS=$value ;;
            detail) WP2SHELL_REFERENCE_LAST_DETAIL=$value ;;
            warning) WP2SHELL_REFERENCE_LAST_WARNING=$value ;;
            source) WP2SHELL_REFERENCE_LAST_SOURCE=$value ;;
            manifest) WP2SHELL_REFERENCE_LAST_MANIFEST=$value ;;
            md5_manifest) WP2SHELL_REFERENCE_LAST_MD5_MANIFEST=$value ;;
            closed) WP2SHELL_REFERENCE_LAST_CLOSED=$value ;;
            entry_count) WP2SHELL_REFERENCE_LAST_ENTRY_COUNT=$value ;;
            fetch_count) WP2SHELL_REFERENCE_FETCH_COUNT=$value ;;
            cap_reached) WP2SHELL_REFERENCE_CAP_REACHED=$value ;;
        esac
    done < "$file"
    case $WP2SHELL_REFERENCE_FETCH_COUNT in
        ''|*[!0-9]*) WP2SHELL_REFERENCE_FETCH_COUNT=0 ;;
    esac
    return 0
}

reference_persist_run_state() {
    local file temp directory
    file=$(reference_result_file)
    directory=$(dirname -- "$file")
    if ! mkdir -p -- "$directory" 2>/dev/null; then
        return 1
    fi
    temp="$file.$BASHPID.tmp"
    {
        printf 'status=%s\n' "$(reference_single_line "$WP2SHELL_REFERENCE_LAST_STATUS")"
        printf 'detail=%s\n' "$(reference_single_line "$WP2SHELL_REFERENCE_LAST_DETAIL")"
        printf 'warning=%s\n' "$(reference_single_line "$WP2SHELL_REFERENCE_LAST_WARNING")"
        printf 'source=%s\n' "$(reference_single_line "$WP2SHELL_REFERENCE_LAST_SOURCE")"
        printf 'manifest=%s\n' "$(reference_single_line "$WP2SHELL_REFERENCE_LAST_MANIFEST")"
        printf 'md5_manifest=%s\n' "$(reference_single_line "$WP2SHELL_REFERENCE_LAST_MD5_MANIFEST")"
        printf 'closed=%s\n' "$WP2SHELL_REFERENCE_LAST_CLOSED"
        printf 'entry_count=%s\n' "$WP2SHELL_REFERENCE_LAST_ENTRY_COUNT"
        printf 'fetch_count=%s\n' "$WP2SHELL_REFERENCE_FETCH_COUNT"
        printf 'cap_reached=%s\n' "$WP2SHELL_REFERENCE_CAP_REACHED"
    } > "$temp" 2>/dev/null || {
        rm -f -- "$temp"
        return 1
    }
    if ! mv -f -- "$temp" "$file" 2>/dev/null; then
        rm -f -- "$temp"
        return 1
    fi
    return 0
}

reference_begin_run() {
    local file
    file=$(reference_result_file)
    rm -f -- "$file"
    WP2SHELL_REFERENCE_FETCH_COUNT=0
    WP2SHELL_REFERENCE_CAP_REACHED=0
    WP2SHELL_REFERENCE_MEMO_STATUS=()
    WP2SHELL_REFERENCE_MEMO_MANIFEST=()
    WP2SHELL_REFERENCE_MEMO_DETAIL=()
    WP2SHELL_REFERENCE_MEMO_WARNING=()
    reference_reset_last_result
    return 0
}

reference_last_status() {
    reference_load_run_state || true
    printf '%s' "$WP2SHELL_REFERENCE_LAST_STATUS"
    return 0
}

reference_last_detail() {
    reference_load_run_state || true
    printf '%s' "$WP2SHELL_REFERENCE_LAST_DETAIL"
    return 0
}

reference_last_warning() {
    reference_load_run_state || true
    printf '%s' "$WP2SHELL_REFERENCE_LAST_WARNING"
    return 0
}

reference_last_source() {
    reference_load_run_state || true
    printf '%s' "$WP2SHELL_REFERENCE_LAST_SOURCE"
    return 0
}

reference_last_entry_count() {
    reference_load_run_state || true
    printf '%s' "$WP2SHELL_REFERENCE_LAST_ENTRY_COUNT"
    return 0
}

reference_last_md5_manifest() {
    reference_load_run_state || true
    printf '%s' "$WP2SHELL_REFERENCE_LAST_MD5_MANIFEST"
    return 0
}

reference_last_package_was_closed() {
    reference_load_run_state || true
    [ "$WP2SHELL_REFERENCE_LAST_CLOSED" = "1" ]
}

reference_last_result_is_failure() {
    reference_load_run_state || true
    reference_status_is_failure "$WP2SHELL_REFERENCE_LAST_STATUS"
}

reference_fetch_count() {
    reference_load_run_state || true
    printf '%s' "$WP2SHELL_REFERENCE_FETCH_COUNT"
    return 0
}

reference_fetch_cap_reached() {
    reference_load_run_state || true
    [ "$WP2SHELL_REFERENCE_CAP_REACHED" = "1" ]
}

reference_status_is_failure() {
    case $1 in
        "$REFERENCE_STATUS_OBTAINED") return 1 ;;
        "$REFERENCE_STATUS_NOT_IN_DIRECTORY") return 1 ;;
        *) return 0 ;;
    esac
}

reference_status_is_cacheable() {
    case $1 in
        "$REFERENCE_STATUS_OBTAINED") return 0 ;;
        "$REFERENCE_STATUS_NOT_IN_DIRECTORY") return 0 ;;
        "$REFERENCE_STATUS_CHECKSUMS_ONLY") return 0 ;;
    esac
    return 1
}

reference_status_dutch_label() {
    case $1 in
        "$REFERENCE_STATUS_OBTAINED")
            printf 'officieel pakket opgehaald' ;;
        "$REFERENCE_STATUS_NOT_IN_DIRECTORY")
            printf 'komt niet voor in de officiele directory, dit is normaal bij premium of maatwerk' ;;
        "$REFERENCE_STATUS_LOOKUP_FAILED")
            printf 'het opvragen of downloaden is mislukt, er is niets vergeleken' ;;
        "$REFERENCE_STATUS_CAP_REACHED")
            printf 'de limiet op het aantal downloads per run is bereikt, er is niets vergeleken' ;;
        "$REFERENCE_STATUS_OFFLINE_MISS")
            printf 'offline modus en niet in de cache, er is niets vergeleken' ;;
        "$REFERENCE_STATUS_UNSUPPORTED")
            printf 'de opgegeven naam of versie is niet bruikbaar als referentie' ;;
        "$REFERENCE_STATUS_ENGINE_UNAVAILABLE")
            printf 'de referentiemotor kan niet draaien op deze server' ;;
        "$REFERENCE_STATUS_UNSAFE_PACKAGE")
            printf 'het opgehaalde archief is afgekeurd door de veiligheidscontrole' ;;
        "$REFERENCE_STATUS_CHECKSUMS_ONLY")
            printf 'alleen de md5-checksums van de core zijn beschikbaar, geen sha256-manifest' ;;
        *)
            printf 'onbekende uitkomst' ;;
    esac
    return 0
}

reference_set_result() {
    WP2SHELL_REFERENCE_LAST_STATUS=$1
    WP2SHELL_REFERENCE_LAST_DETAIL=$2
    log_debug "reference: status=$1 detail=$2"
    return 0
}

reference_reset_last_result() {
    WP2SHELL_REFERENCE_LAST_STATUS="$REFERENCE_STATUS_UNKNOWN"
    WP2SHELL_REFERENCE_LAST_DETAIL="Er is geen uitkomst vastgelegd."
    WP2SHELL_REFERENCE_LAST_WARNING=""
    WP2SHELL_REFERENCE_LAST_SOURCE=""
    WP2SHELL_REFERENCE_LAST_MANIFEST=""
    WP2SHELL_REFERENCE_LAST_MD5_MANIFEST=""
    WP2SHELL_REFERENCE_LAST_CLOSED=0
    WP2SHELL_REFERENCE_LAST_ENTRY_COUNT=0
    return 0
}

reference_kind_is_supported() {
    case $1 in
        core|plugin|theme) return 0 ;;
    esac
    return 1
}

reference_slug_is_valid() {
    local slug=$1
    case $slug in
        ''|.*|*/*|*..*) return 1 ;;
    esac
    [[ $slug =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]]
}

reference_version_is_valid() {
    local version=$1
    case $version in
        ''|*/*|*..*) return 1 ;;
        trunk|latest|master|main|dev) return 1 ;;
    esac
    [[ $version =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$ ]]
}

reference_locale_is_valid() {
    [[ $1 =~ ^[a-z]{2,3}(_[A-Z]{2})?$ ]]
}

reference_package_directory() {
    local kind=$1 slug=$2 version=$3 locale=$4
    case $kind in
        core) printf '%s/core/%s/%s' "$(reference_cache_packages_dir)" "$locale" "$version" ;;
        *) printf '%s/%s/%s/%s' "$(reference_cache_packages_dir)" "$kind" "$slug" "$version" ;;
    esac
    return 0
}

reference_memo_key() {
    local kind=$1 slug=$2 version=$3 locale=$4
    case $kind in
        core) printf 'core|%s|%s' "$locale" "$version" ;;
        *) printf '%s|%s|%s' "$kind" "$slug" "$version" ;;
    esac
    return 0
}

reference_file_sha256() {
    local target=$1 output
    case ${WP2SHELL_REFERENCE_SHA256_TOOL:-none} in
        sha256sum)
            output=$(sha256sum -- "$target" 2>/dev/null) || return 1
            output=${output%% *}
            printf '%s' "${output#\\}"
            return 0
            ;;
        openssl)
            output=$(openssl dgst -sha256 -- "$target" 2>/dev/null) || return 1
            printf '%s' "${output##* }"
            return 0
            ;;
    esac
    return 1
}

reference_load_prefix() {
    if [ -z "${WP2SHELL_LOAD_PREFIX[*]+x}" ]; then
        build_load_prefix
    fi
    return 0
}

reference_engine_available() {
    if [ "${WP2SHELL_REFERENCE_ENGINE_CHECKED:-0}" = "1" ]; then
        if [ "$WP2SHELL_REFERENCE_ENGINE_OK" = "1" ]; then
            return 0
        fi
        return 1
    fi
    WP2SHELL_REFERENCE_ENGINE_CHECKED=1
    WP2SHELL_REFERENCE_ENGINE_OK=0
    WP2SHELL_REFERENCE_ENGINE_REASON=""
    local missing=""
    if have_command sha256sum; then
        WP2SHELL_REFERENCE_SHA256_TOOL=sha256sum
    elif have_command openssl; then
        WP2SHELL_REFERENCE_SHA256_TOOL=openssl
    else
        WP2SHELL_REFERENCE_SHA256_TOOL=none
        missing="$missing sha256sum"
    fi
    if have_command python3; then
        WP2SHELL_REFERENCE_EXTRACTOR=python3
        WP2SHELL_REFERENCE_JSON_TOOL=python3
    elif have_command unzip; then
        WP2SHELL_REFERENCE_EXTRACTOR=unzip
        WP2SHELL_REFERENCE_JSON_TOOL=none
    else
        WP2SHELL_REFERENCE_EXTRACTOR=none
        WP2SHELL_REFERENCE_JSON_TOOL=none
        missing="$missing python3-of-unzip"
    fi
    local offline=${WP2SHELL_REFERENCE_OFFLINE:-0}
    if [ "$offline" != "1" ] && ! have_command curl; then
        missing="$missing curl"
    fi
    local root packages work
    root=$(reference_cache_root)
    packages=$(reference_cache_packages_dir)
    work=$(reference_cache_work_dir)
    if ! mkdir -p -- "$packages" "$work" 2>/dev/null; then
        missing="$missing schrijfbare-cache($root)"
    elif [ ! -w "$packages" ] || [ ! -w "$work" ]; then
        missing="$missing schrijfbare-cache($root)"
    fi
    if [ -n "$missing" ]; then
        WP2SHELL_REFERENCE_ENGINE_REASON="Ontbrekende voorwaarden voor de referentiemotor:${missing}. Zonder deze onderdelen kan geen enkel officieel pakket opgehaald of vergeleken worden."
        log_warn "$WP2SHELL_REFERENCE_ENGINE_REASON"
        return 1
    fi
    WP2SHELL_REFERENCE_ENGINE_OK=1
    log_debug "reference: cache=$root extractor=$WP2SHELL_REFERENCE_EXTRACTOR json=$WP2SHELL_REFERENCE_JSON_TOOL hash=$WP2SHELL_REFERENCE_SHA256_TOOL offline=$offline"
    return 0
}

reference_engine_unavailable_reason() {
    printf '%s' "$WP2SHELL_REFERENCE_ENGINE_REASON"
    return 0
}

reference_engine_summary() {
    reference_load_run_state || true
    printf 'cache %s, uitpakker %s, json %s, opgehaald %s van maximaal %s, offline %s' \
        "$(reference_cache_root)" \
        "$WP2SHELL_REFERENCE_EXTRACTOR" \
        "$WP2SHELL_REFERENCE_JSON_TOOL" \
        "$WP2SHELL_REFERENCE_FETCH_COUNT" \
        "${WP2SHELL_REFERENCE_MAX_FETCHES_PER_RUN:-60}" \
        "${WP2SHELL_REFERENCE_OFFLINE:-0}"
    return 0
}

reference_curl_base_arguments() {
    WP2SHELL_REFERENCE_CURL_ARGS=(
        --silent
        --show-error
        --location
        --proto '=https'
        --proto-redir '=https'
        --connect-timeout "${WP2SHELL_REFERENCE_CONNECT_TIMEOUT:-15}"
        --max-time "${WP2SHELL_REFERENCE_MAX_TIME:-120}"
        --retry "${WP2SHELL_REFERENCE_RETRY:-2}"
        --retry-delay "${WP2SHELL_REFERENCE_RETRY_DELAY:-5}"
        --retry-connrefused
        --user-agent "$(reference_user_agent)"
    )
    if [ -n "${WP2SHELL_REFERENCE_LIMIT_RATE:-}" ]; then
        WP2SHELL_REFERENCE_CURL_ARGS+=(--limit-rate "$WP2SHELL_REFERENCE_LIMIT_RATE")
    fi
    return 0
}

reference_network_is_allowed() {
    [ "${WP2SHELL_REFERENCE_OFFLINE:-0}" != "1" ]
}

reference_polite_delay() {
    local seconds=${WP2SHELL_REFERENCE_FETCH_DELAY_SECONDS:-1}
    case $seconds in
        ''|*[!0-9]*) return 0 ;;
    esac
    if [ "$seconds" -gt 0 ]; then
        sleep "$seconds"
    fi
    return 0
}

reference_http_get_body() {
    local url=$1 destination=$2
    WP2SHELL_REFERENCE_HTTP_OUTCOME=failed
    WP2SHELL_REFERENCE_HTTP_CODE=""
    WP2SHELL_REFERENCE_HTTP_RC=0
    if ! reference_network_is_allowed; then
        log_warn "Netwerktoegang is uitgeschakeld, $url wordt niet opgevraagd"
        return 1
    fi
    reference_curl_base_arguments
    local code='' rc=0
    code=$(curl "${WP2SHELL_REFERENCE_CURL_ARGS[@]}" \
        --max-filesize "${WP2SHELL_REFERENCE_MAX_JSON_BYTES:-16777216}" \
        --output "$destination" \
        --write-out '%{http_code}' \
        -- "$url" 2>/dev/null) || rc=$?
    WP2SHELL_REFERENCE_HTTP_CODE=$code
    WP2SHELL_REFERENCE_HTTP_RC=$rc
    reference_polite_delay
    if [ "$rc" -eq 0 ] && [ "$code" = "200" ]; then
        WP2SHELL_REFERENCE_HTTP_OUTCOME=ok
        return 0
    fi
    if [ "$rc" -eq 0 ] && [ "$code" = "404" ]; then
        WP2SHELL_REFERENCE_HTTP_OUTCOME=notfound
        return 1
    fi
    WP2SHELL_REFERENCE_HTTP_OUTCOME=failed
    log_warn "Opvragen van $url is mislukt, curl-exitcode $rc en http-status ${code:-geen}"
    return 1
}

reference_http_download() {
    local url=$1 destination=$2
    WP2SHELL_REFERENCE_HTTP_OUTCOME=failed
    WP2SHELL_REFERENCE_HTTP_CODE=""
    WP2SHELL_REFERENCE_HTTP_RC=0
    if ! reference_network_is_allowed; then
        log_warn "Netwerktoegang is uitgeschakeld, $url wordt niet gedownload"
        return 1
    fi
    reference_curl_base_arguments
    local code='' rc=0
    code=$(curl "${WP2SHELL_REFERENCE_CURL_ARGS[@]}" \
        --fail \
        --max-filesize "${WP2SHELL_REFERENCE_MAX_DOWNLOAD_BYTES:-62914560}" \
        --output "$destination" \
        --write-out '%{http_code}' \
        -- "$url" 2>/dev/null) || rc=$?
    WP2SHELL_REFERENCE_HTTP_CODE=$code
    WP2SHELL_REFERENCE_HTTP_RC=$rc
    reference_polite_delay
    if [ "$rc" -eq 0 ] && [ -s "$destination" ]; then
        WP2SHELL_REFERENCE_HTTP_OUTCOME=ok
        return 0
    fi
    if [ "$rc" -eq 22 ] && [ "$code" = "404" ]; then
        WP2SHELL_REFERENCE_HTTP_OUTCOME=notfound
        rm -f -- "$destination"
        return 1
    fi
    if [ "$rc" -eq 63 ]; then
        WP2SHELL_REFERENCE_HTTP_OUTCOME=toolarge
        log_warn "Download van $url is afgebroken omdat het bestand groter is dan de ingestelde limiet"
        rm -f -- "$destination"
        return 1
    fi
    WP2SHELL_REFERENCE_HTTP_OUTCOME=failed
    log_warn "Download van $url is mislukt, curl-exitcode $rc en http-status ${code:-geen}"
    rm -f -- "$destination"
    return 1
}

reference_manifest_is_wellformed() {
    local manifest=$1 length=$2
    if [ ! -s "$manifest" ]; then
        return 1
    fi
    local pattern rc=0
    pattern="^[0-9a-f]{$length}$(printf '\t')."
    "${WP2SHELL_GREP:-grep}" -q -v -E -e "$pattern" -- "$manifest" || rc=$?
    case $rc in
        1) return 0 ;;
        *) return 1 ;;
    esac
}

reference_manifest_line_count() {
    local manifest=$1 count
    count=$(wc -l < "$manifest" 2>/dev/null) || count=0
    count=${count// /}
    case $count in
        ''|*[!0-9]*) count=0 ;;
    esac
    printf '%s' "$count"
    return 0
}

reference_core_checksums_to_manifest() {
    local source_file=$1 destination=$2 rc=0
    if [ "$WP2SHELL_REFERENCE_JSON_TOOL" != "python3" ]; then
        return 3
    fi
    python3 - "$source_file" "$destination" <<'REFERENCE_PYTHON' || rc=$?
import json
import sys

source_path, destination_path = sys.argv[1], sys.argv[2]
try:
    with open(source_path, 'rb') as handle:
        data = json.loads(handle.read().decode('utf-8', 'replace'))
except Exception:
    sys.exit(3)
if not isinstance(data, dict):
    sys.exit(3)
sums = data.get('checksums')
if not isinstance(sums, dict) or not sums:
    sys.exit(4)
allowed = set('0123456789abcdef')
lines = []
for path, value in sums.items():
    if not isinstance(path, str) or not isinstance(value, str):
        sys.exit(3)
    digest = value.lower()
    if len(digest) != 32 or not set(digest) <= allowed:
        sys.exit(3)
    if path.startswith('/') or '..' in path.split('/'):
        sys.exit(3)
    if '\t' in path or '\n' in path or '\r' in path or '\x00' in path:
        sys.exit(3)
    lines.append(digest + '\t' + path)
lines.sort()
with open(destination_path, 'w', encoding='utf-8') as handle:
    handle.write('\n'.join(lines))
    handle.write('\n')
REFERENCE_PYTHON
    return "$rc"
}

reference_plugin_checksums_to_manifest() {
    local source_file=$1 destination=$2 slug=$3 version=$4 rc=0
    if [ "$WP2SHELL_REFERENCE_JSON_TOOL" != "python3" ]; then
        return 3
    fi
    python3 - "$source_file" "$destination" "$slug" "$version" <<'REFERENCE_PYTHON' || rc=$?
import json
import sys

source_path, destination_path = sys.argv[1], sys.argv[2]
expected_slug, expected_version = sys.argv[3], sys.argv[4]
try:
    with open(source_path, 'rb') as handle:
        data = json.loads(handle.read().decode('utf-8', 'replace'))
except Exception:
    sys.exit(3)
if not isinstance(data, dict):
    sys.exit(3)
answered_slug = data.get('plugin')
answered_version = data.get('version')
if isinstance(answered_slug, str) and answered_slug.lower() != expected_slug.lower():
    sys.exit(5)
if isinstance(answered_version, str) and answered_version != expected_version:
    sys.exit(5)
files = data.get('files')
if not isinstance(files, dict) or not files:
    sys.exit(4)
allowed = set('0123456789abcdef')
lines = []
for path, entry in files.items():
    if not isinstance(path, str) or not isinstance(entry, dict):
        sys.exit(3)
    value = entry.get('sha256')
    if not isinstance(value, str):
        sys.exit(3)
    digest = value.lower()
    if len(digest) != 64 or not set(digest) <= allowed:
        sys.exit(3)
    if path.startswith('/') or '..' in path.split('/'):
        sys.exit(3)
    if '\t' in path or '\n' in path or '\r' in path or '\x00' in path:
        sys.exit(3)
    lines.append(digest + '\t' + path)
lines.sort()
with open(destination_path, 'w', encoding='utf-8') as handle:
    handle.write('\n'.join(lines))
    handle.write('\n')
REFERENCE_PYTHON
    return "$rc"
}

reference_package_info_to_fields() {
    local source_file=$1 destination=$2 wanted_version=$3 rc=0
    if [ "$WP2SHELL_REFERENCE_JSON_TOOL" != "python3" ]; then
        return 3
    fi
    python3 - "$source_file" "$destination" "$wanted_version" <<'REFERENCE_PYTHON' || rc=$?
import json
import sys

source_path, destination_path, wanted = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(source_path, 'rb') as handle:
        data = json.loads(handle.read().decode('utf-8', 'replace'))
except Exception:
    sys.exit(3)

def clean(value):
    if not isinstance(value, str):
        return ''
    out = value.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ')
    out = out.replace('\x00', '')
    return out[:200]

fields = {
    'present': '0',
    'error': '',
    'closed': '0',
    'slug': '',
    'version': '',
    'versions_present': '0',
    'version_known': '0',
    'version_url': '',
    'download_link': '',
    'template': '',
}
if isinstance(data, dict):
    fields['present'] = '1'
    fields['error'] = clean(data.get('error'))
    if data.get('closed') is True or fields['error'] == 'closed':
        fields['closed'] = '1'
    fields['slug'] = clean(data.get('slug'))
    fields['version'] = clean(data.get('version'))
    fields['download_link'] = clean(data.get('download_link'))
    fields['template'] = clean(data.get('template'))
    versions = data.get('versions')
    if isinstance(versions, dict) and versions:
        fields['versions_present'] = '1'
        if wanted in versions:
            fields['version_known'] = '1'
            fields['version_url'] = clean(versions.get(wanted))
with open(destination_path, 'w', encoding='utf-8') as handle:
    for key in sorted(fields):
        handle.write(key + '=' + fields[key] + '\n')
REFERENCE_PYTHON
    return "$rc"
}

reference_url_is_official_download() {
    case $1 in
        https://downloads.wordpress.org/*) return 0 ;;
    esac
    return 1
}

reference_extract_with_python() {
    local archive=$1 destination=$2 max_bytes=$3 max_entries=$4 rc=0
    local -a prefix=()
    reference_load_prefix
    if [ -n "${WP2SHELL_LOAD_PREFIX[*]+x}" ]; then
        prefix=("${WP2SHELL_LOAD_PREFIX[@]}")
    fi
    "${prefix[@]+"${prefix[@]}"}" python3 - "$archive" "$destination" "$max_bytes" "$max_entries" <<'REFERENCE_PYTHON' || rc=$?
import os
import stat
import sys
import zipfile

archive_path = sys.argv[1]
destination = sys.argv[2]
max_bytes = int(sys.argv[3])
max_entries = int(sys.argv[4])

def reject(message):
    sys.stderr.write(message + '\n')
    sys.exit(2)

try:
    archive = zipfile.ZipFile(archive_path)
except Exception as exc:
    reject('archief kan niet geopend worden: %s' % exc)

entries = archive.infolist()
if len(entries) > max_entries:
    reject('archief bevat te veel entries: %d' % len(entries))

seen = set()
total = 0
for info in entries:
    name = info.filename
    if not name:
        reject('archief bevat een lege naam')
    if name.startswith('/') or name.startswith('\\'):
        reject('archief bevat een absoluut pad: %r' % name)
    if '\\' in name or '\x00' in name or '\n' in name or '\r' in name:
        reject('archief bevat een onbruikbaar teken in een naam: %r' % name)
    parts = name.split('/')
    if '..' in parts:
        reject('archief bevat een bovenliggend pad: %r' % name)
    if len(parts[0]) == 2 and parts[0][1] == ':':
        reject('archief bevat een pad met een stationsaanduiding: %r' % name)
    mode = info.external_attr >> 16
    if stat.S_ISLNK(mode):
        reject('archief bevat een symlink: %r' % name)
    if info.is_dir():
        continue
    if mode != 0 and not stat.S_ISREG(mode):
        reject('archief bevat een bestand dat geen gewoon bestand is: %r' % name)
    if name in seen:
        reject('archief bevat dezelfde naam twee keer: %r' % name)
    seen.add(name)
    total += info.file_size
    if total > max_bytes:
        reject('uitgepakte omvang overschrijdt de limiet van %d bytes' % max_bytes)

os.makedirs(destination, exist_ok=True)
root = os.path.realpath(destination)
written = 0
for info in entries:
    name = info.filename
    target = os.path.realpath(os.path.join(root, name))
    if target != root and not target.startswith(root + os.sep):
        reject('doelpad valt buiten de cachemap: %r' % name)
    if info.is_dir():
        os.makedirs(target, exist_ok=True)
        continue
    parent = os.path.dirname(target)
    os.makedirs(parent, exist_ok=True)
    try:
        handle = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        reject('kan %r niet aanmaken: %s' % (name, exc))
    with os.fdopen(handle, 'wb') as output:
        with archive.open(info) as source:
            while True:
                chunk = source.read(262144)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    reject('uitgepakte omvang overschrijdt de limiet tijdens het schrijven')
                output.write(chunk)
sys.exit(0)
REFERENCE_PYTHON
    if [ "$rc" -ne 0 ]; then
        log_warn "Uitpakken met python3 is afgekeurd of mislukt voor $archive, exitcode $rc"
        return 1
    fi
    return 0
}

reference_unzip_listing_is_safe() {
    local archive=$1 listing rc=0 entry status=0
    listing=$(mktemp -t wp2shell-reference-listing.XXXXXXXX) || return 1
    register_temp_cleanup "$listing"
    unzip -Z1 -- "$archive" > "$listing" 2>/dev/null || status=$?
    if [ "$status" -ne 0 ]; then
        log_warn "De inhoudsopgave van $archive kon niet gelezen worden, exitcode $status"
        rm -f -- "$listing"
        return 1
    fi
    while IFS= read -r entry || [ -n "$entry" ]; do
        case $entry in
            '') continue ;;
            /*|\\*|*/../*|../*|*/..|..)
                log_warn "Archief $archive bevat een onveilig pad en wordt afgekeurd"
                rc=1
                break
                ;;
            *\\*)
                log_warn "Archief $archive bevat een backslash in een pad en wordt afgekeurd"
                rc=1
                break
                ;;
        esac
    done < "$listing"
    rm -f -- "$listing"
    return "$rc"
}

reference_extract_with_unzip() {
    local archive=$1 destination=$2 max_bytes=$3 max_entries=$4
    local summary entries bytes status=0
    summary=$(unzip -Zt -- "$archive" 2>/dev/null) || status=$?
    if [ "$status" -ne 0 ] || [ -z "$summary" ]; then
        log_warn "Kan de samenvatting van $archive niet lezen"
        return 1
    fi
    entries=$(printf '%s\n' "$summary" | awk 'NR==1 {print $1}')
    bytes=$(printf '%s\n' "$summary" | awk 'NR==1 {print $3}')
    case $entries in
        ''|*[!0-9]*)
            log_warn "Onverwachte samenvatting voor $archive, het archief wordt niet uitgepakt"
            return 1
            ;;
    esac
    case $bytes in
        ''|*[!0-9]*)
            log_warn "Onverwachte samenvatting voor $archive, het archief wordt niet uitgepakt"
            return 1
            ;;
    esac
    if [ "$entries" -gt "$max_entries" ]; then
        log_warn "Archief $archive bevat $entries entries en overschrijdt de limiet van $max_entries"
        return 1
    fi
    if [ "$bytes" -gt "$max_bytes" ]; then
        log_warn "Archief $archive is uitgepakt $bytes bytes en overschrijdt de limiet van $max_bytes"
        return 1
    fi
    if ! reference_unzip_listing_is_safe "$archive"; then
        return 1
    fi
    local -a prefix=()
    reference_load_prefix
    if [ -n "${WP2SHELL_LOAD_PREFIX[*]+x}" ]; then
        prefix=("${WP2SHELL_LOAD_PREFIX[@]}")
    fi
    status=0
    "${prefix[@]+"${prefix[@]}"}" unzip -qq -o -- "$archive" -d "$destination" >/dev/null 2>&1 || status=$?
    if [ "$status" -ne 0 ]; then
        log_warn "Uitpakken met unzip is mislukt voor $archive, exitcode $status"
        return 1
    fi
    return 0
}

reference_tree_is_safe() {
    local root=$1 listing status=0 entry unsafe=0
    listing=$(mktemp -t wp2shell-reference-sweep.XXXXXXXX) || return 1
    register_temp_cleanup "$listing"
    "${WP2SHELL_FIND:-find}" -P "$root" ! -type f ! -type d -print0 > "$listing" 2>/dev/null || status=$?
    if [ "$status" -ne 0 ]; then
        log_warn "De veiligheidscontrole op de uitgepakte boom $root is niet voltooid, exitcode $status"
        rm -f -- "$listing"
        return 1
    fi
    while IFS= read -r -d '' entry; do
        unsafe=1
        log_warn "Uitgepakt pakket bevat een symlink of een speciaal bestand en wordt afgekeurd: $entry"
    done < "$listing"
    rm -f -- "$listing"
    if [ "$unsafe" = "1" ]; then
        return 1
    fi
    return 0
}

reference_extract_archive() {
    local archive=$1 destination=$2
    local max_bytes=${WP2SHELL_REFERENCE_MAX_UNCOMPRESSED_BYTES:-209715200}
    local max_entries=${WP2SHELL_REFERENCE_MAX_ENTRIES:-20000}
    case $max_bytes in
        ''|*[!0-9]*) max_bytes=209715200 ;;
    esac
    case $max_entries in
        ''|*[!0-9]*) max_entries=20000 ;;
    esac
    if ! mkdir -p -- "$destination" 2>/dev/null; then
        log_warn "Kan de uitpakmap $destination niet aanmaken"
        return 1
    fi
    local extracted=0
    case ${WP2SHELL_REFERENCE_EXTRACTOR:-none} in
        python3)
            if reference_extract_with_python "$archive" "$destination" "$max_bytes" "$max_entries"; then
                extracted=1
            fi
            ;;
        unzip)
            if reference_extract_with_unzip "$archive" "$destination" "$max_bytes" "$max_entries"; then
                extracted=1
            fi
            ;;
        *)
            log_warn "Er is geen bruikbare uitpakker beschikbaar, $archive blijft ongebruikt"
            ;;
    esac
    if [ "$extracted" != "1" ]; then
        return 1
    fi
    if ! reference_tree_is_safe "$destination"; then
        return 1
    fi
    return 0
}

reference_package_root_in_tree() {
    local tree=$1 preferred=$2
    if [ -n "$preferred" ] && [ -d "$tree/$preferred" ]; then
        printf '%s' "$tree/$preferred"
        return 0
    fi
    local listing status=0 entry single='' count=0
    listing=$(mktemp -t wp2shell-reference-root.XXXXXXXX) || return 1
    register_temp_cleanup "$listing"
    "${WP2SHELL_FIND:-find}" -P "$tree" -mindepth 1 -maxdepth 1 -print0 > "$listing" 2>/dev/null || status=$?
    if [ "$status" -ne 0 ]; then
        rm -f -- "$listing"
        return 1
    fi
    while IFS= read -r -d '' entry; do
        count=$((count + 1))
        single=$entry
    done < "$listing"
    rm -f -- "$listing"
    if [ "$count" -eq 1 ] && [ -d "$single" ]; then
        printf '%s' "$single"
        return 0
    fi
    printf '%s' "$tree"
    return 0
}

reference_build_manifest_from_tree() {
    local root=$1 manifest=$2
    root=${root%/}
    local listing status=0 entry relative digest count=0 skipped=0
    listing=$(mktemp -t wp2shell-reference-files.XXXXXXXX) || return 1
    register_temp_cleanup "$listing"
    "${WP2SHELL_FIND:-find}" -P "$root" -type f -print0 > "$listing" 2>/dev/null || status=$?
    if [ "$status" -ne 0 ]; then
        log_warn "Het doorlopen van $root is mislukt, exitcode $status"
        rm -f -- "$listing"
        return 1
    fi
    local unsorted
    unsorted=$(mktemp -t wp2shell-reference-manifest.XXXXXXXX) || {
        rm -f -- "$listing"
        return 1
    }
    register_temp_cleanup "$unsorted"
    : > "$unsorted"
    local failed=0
    while IFS= read -r -d '' entry; do
        relative=${entry#"$root"/}
        if [ "$relative" = "$entry" ]; then
            continue
        fi
        case $relative in
            *$'\t'*|*$'\n'*)
                skipped=$((skipped + 1))
                continue
                ;;
        esac
        digest=$(reference_file_sha256 "$entry") || digest=''
        if [ "${#digest}" -ne 64 ]; then
            log_warn "Kan geen sha256 berekenen voor $entry, het manifest wordt verworpen"
            failed=1
            break
        fi
        printf '%s\t%s\n' "${digest,,}" "$relative" >> "$unsorted"
        count=$((count + 1))
    done < "$listing"
    rm -f -- "$listing"
    if [ "$failed" = "1" ]; then
        rm -f -- "$unsorted"
        return 1
    fi
    if [ "$skipped" -gt 0 ]; then
        log_warn "$skipped bestanden uit het officiele pakket hebben een tab of newline in de naam en staan niet in het manifest"
    fi
    if [ "$count" -eq 0 ]; then
        rm -f -- "$unsorted"
        return 1
    fi
    if ! LC_ALL=C "${WP2SHELL_SORT:-sort}" "$unsorted" > "$manifest" 2>/dev/null; then
        rm -f -- "$unsorted"
        return 1
    fi
    rm -f -- "$unsorted"
    return 0
}

reference_download_and_build_manifest() {
    local url=$1 work_dir=$2 preferred_root=$3
    WP2SHELL_REFERENCE_DOWNLOAD_OUTCOME=failed
    local archive="$work_dir/package.zip"
    local tree="$work_dir/tree"
    if ! reference_http_download "$url" "$archive"; then
        case $WP2SHELL_REFERENCE_HTTP_OUTCOME in
            notfound) WP2SHELL_REFERENCE_DOWNLOAD_OUTCOME=notfound ;;
            toolarge) WP2SHELL_REFERENCE_DOWNLOAD_OUTCOME=unsafe ;;
            *) WP2SHELL_REFERENCE_DOWNLOAD_OUTCOME=failed ;;
        esac
        return 1
    fi
    if ! reference_extract_archive "$archive" "$tree"; then
        WP2SHELL_REFERENCE_DOWNLOAD_OUTCOME=unsafe
        rm -rf -- "$tree"
        rm -f -- "$archive"
        return 1
    fi
    local package_root
    if ! package_root=$(reference_package_root_in_tree "$tree" "$preferred_root"); then
        WP2SHELL_REFERENCE_DOWNLOAD_OUTCOME=failed
        return 1
    fi
    if ! path_is_within "$package_root" "$tree"; then
        WP2SHELL_REFERENCE_DOWNLOAD_OUTCOME=unsafe
        log_warn "De hoofdmap van het pakket valt buiten de uitpakmap, het pakket wordt afgekeurd"
        return 1
    fi
    if ! reference_build_manifest_from_tree "$package_root" "$work_dir/manifest.tsv"; then
        WP2SHELL_REFERENCE_DOWNLOAD_OUTCOME=failed
        return 1
    fi
    if ! reference_manifest_is_wellformed "$work_dir/manifest.tsv" 64; then
        WP2SHELL_REFERENCE_DOWNLOAD_OUTCOME=failed
        log_warn "Het opgebouwde manifest voor $url is niet bruikbaar"
        return 1
    fi
    if [ "${WP2SHELL_REFERENCE_KEEP_TREE:-1}" != "1" ]; then
        rm -rf -- "$tree"
    fi
    if [ "${WP2SHELL_REFERENCE_KEEP_ARCHIVE:-0}" != "1" ]; then
        rm -f -- "$archive"
    fi
    WP2SHELL_REFERENCE_DOWNLOAD_OUTCOME=ok
    return 0
}

reference_read_info_fields() {
    local fields_file=$1
    WP2SHELL_REFERENCE_INFO_PRESENT=0
    WP2SHELL_REFERENCE_INFO_ERROR=""
    WP2SHELL_REFERENCE_INFO_CLOSED=0
    WP2SHELL_REFERENCE_INFO_SLUG=""
    WP2SHELL_REFERENCE_INFO_VERSION=""
    WP2SHELL_REFERENCE_INFO_VERSIONS_PRESENT=0
    WP2SHELL_REFERENCE_INFO_VERSION_KNOWN=0
    WP2SHELL_REFERENCE_INFO_VERSION_URL=""
    WP2SHELL_REFERENCE_INFO_DOWNLOAD_LINK=""
    WP2SHELL_REFERENCE_INFO_TEMPLATE=""
    local line key value
    while IFS= read -r line || [ -n "$line" ]; do
        key=${line%%=*}
        value=${line#*=}
        case $key in
            present) WP2SHELL_REFERENCE_INFO_PRESENT=$value ;;
            error) WP2SHELL_REFERENCE_INFO_ERROR=$value ;;
            closed) WP2SHELL_REFERENCE_INFO_CLOSED=$value ;;
            slug) WP2SHELL_REFERENCE_INFO_SLUG=$value ;;
            version) WP2SHELL_REFERENCE_INFO_VERSION=$value ;;
            versions_present) WP2SHELL_REFERENCE_INFO_VERSIONS_PRESENT=$value ;;
            version_known) WP2SHELL_REFERENCE_INFO_VERSION_KNOWN=$value ;;
            version_url) WP2SHELL_REFERENCE_INFO_VERSION_URL=$value ;;
            download_link) WP2SHELL_REFERENCE_INFO_DOWNLOAD_LINK=$value ;;
            template) WP2SHELL_REFERENCE_INFO_TEMPLATE=$value ;;
        esac
    done < "$fields_file"
    return 0
}

reference_query_package_info() {
    local url=$1 version=$2 work_dir=$3
    local body="$work_dir/info.json"
    local fields="$work_dir/info.fields"
    local outcome status
    reference_http_get_body "$url" "$body" || true
    outcome=$WP2SHELL_REFERENCE_HTTP_OUTCOME
    if [ "$outcome" = "failed" ]; then
        return 1
    fi
    status=0
    reference_package_info_to_fields "$body" "$fields" "$version" || status=$?
    if [ "$status" -ne 0 ]; then
        reference_read_info_fields /dev/null
        if [ "$outcome" = "notfound" ]; then
            return 2
        fi
        return 3
    fi
    reference_read_info_fields "$fields"
    if [ "$outcome" = "notfound" ]; then
        return 2
    fi
    return 0
}

reference_fetch_plugin_package() {
    local slug=$1 version=$2 work_dir=$3
    local checksum_url="https://downloads.wordpress.org/plugin-checksums/$slug/$version.json"
    local body="$work_dir/checksums.json"
    local status=0
    if reference_http_get_body "$checksum_url" "$body"; then
        status=0
        reference_plugin_checksums_to_manifest "$body" "$work_dir/manifest.tsv" "$slug" "$version" || status=$?
        if [ "$status" -eq 5 ]; then
            log_warn "De checksums die wordpress.org teruggaf horen niet bij plugin $slug versie $version, ze worden niet gebruikt"
        fi
        if [ "$status" -eq 0 ] && reference_manifest_is_wellformed "$work_dir/manifest.tsv" 64; then
            WP2SHELL_REFERENCE_LAST_SOURCE="plugin-checksums"
            reference_set_result "$REFERENCE_STATUS_OBTAINED" \
                "De officiele sha256-checksums van plugin $slug versie $version zijn opgehaald bij wordpress.org, zonder het pakket te downloaden."
            return 0
        fi
        log_warn "De checksums van plugin $slug versie $version zijn niet bruikbaar, er wordt teruggevallen op het pakket zelf"
        rm -f -- "$work_dir/manifest.tsv"
    elif [ "$WP2SHELL_REFERENCE_HTTP_OUTCOME" = "failed" ]; then
        reference_set_result "$REFERENCE_STATUS_LOOKUP_FAILED" \
            "Het opvragen van de checksums van plugin $slug versie $version is mislukt. Deze plugin is niet vergeleken."
        return 1
    fi
    local info_url="https://api.wordpress.org/plugins/info/1.0/$slug.json"
    local info_status=0
    if [ "$WP2SHELL_REFERENCE_JSON_TOOL" != "python3" ]; then
        reference_read_info_fields /dev/null
        WP2SHELL_REFERENCE_LAST_WARNING="Er is geen json-lezer beschikbaar, dus de gegevens van plugin $slug zijn niet bij wordpress.org gecontroleerd en een gesloten plugin wordt niet als zodanig herkend."
        log_warn "$WP2SHELL_REFERENCE_LAST_WARNING"
    else
        reference_query_package_info "$info_url" "$version" "$work_dir" || info_status=$?
    fi
    case $info_status in
        0)
            if [ "$WP2SHELL_REFERENCE_INFO_VERSIONS_PRESENT" = "1" ] && [ "$WP2SHELL_REFERENCE_INFO_VERSION_KNOWN" != "1" ]; then
                reference_set_result "$REFERENCE_STATUS_NOT_IN_DIRECTORY" \
                    "Plugin $slug staat wel in de directory maar versie $version is daar niet als uitgebrachte versie bekend. Er is geen origineel om mee te vergelijken."
                return 1
            fi
            ;;
        2)
            if [ "$WP2SHELL_REFERENCE_INFO_CLOSED" = "1" ]; then
                WP2SHELL_REFERENCE_LAST_CLOSED=1
                WP2SHELL_REFERENCE_LAST_WARNING="Plugin $slug is door wordpress.org gesloten. De checksums zijn ingetrokken maar het pakket is nog wel op te halen. Een gesloten plugin is vaker wel dan niet de reden van de inbraak."
                log_warn "$WP2SHELL_REFERENCE_LAST_WARNING"
            else
                reference_set_result "$REFERENCE_STATUS_NOT_IN_DIRECTORY" \
                    "Plugin $slug komt niet voor in de officiele directory. Dat is normaal bij premium plugins en bij maatwerk, en betekent alleen dat er geen origineel is om mee te vergelijken."
                return 1
            fi
            ;;
        *)
            reference_set_result "$REFERENCE_STATUS_LOOKUP_FAILED" \
                "Het opvragen van de gegevens van plugin $slug bij wordpress.org is mislukt. Deze plugin is niet vergeleken."
            return 1
            ;;
    esac
    local zip_url="https://downloads.wordpress.org/plugin/$slug.$version.zip"
    if [ -n "$WP2SHELL_REFERENCE_INFO_VERSION_URL" ] &&
        reference_url_is_official_download "$WP2SHELL_REFERENCE_INFO_VERSION_URL"; then
        zip_url=$WP2SHELL_REFERENCE_INFO_VERSION_URL
    fi
    if reference_download_and_build_manifest "$zip_url" "$work_dir" "$slug"; then
        WP2SHELL_REFERENCE_LAST_SOURCE="plugin-zip"
        reference_set_result "$REFERENCE_STATUS_OBTAINED" \
            "Het officiele pakket van plugin $slug versie $version is gedownload en uitgepakt, en het manifest is daaruit opgebouwd."
        return 0
    fi
    case $WP2SHELL_REFERENCE_DOWNLOAD_OUTCOME in
        notfound)
            reference_set_result "$REFERENCE_STATUS_NOT_IN_DIRECTORY" \
                "Van plugin $slug is versie $version niet als pakket beschikbaar bij wordpress.org. Er is geen origineel om mee te vergelijken."
            ;;
        unsafe)
            reference_set_result "$REFERENCE_STATUS_UNSAFE_PACKAGE" \
                "Het opgehaalde pakket van plugin $slug versie $version is door de veiligheidscontrole afgekeurd en niet gebruikt."
            ;;
        *)
            reference_set_result "$REFERENCE_STATUS_LOOKUP_FAILED" \
                "Het downloaden van plugin $slug versie $version is mislukt. Deze plugin is niet vergeleken."
            ;;
    esac
    return 1
}

reference_fetch_theme_package() {
    local slug=$1 version=$2 work_dir=$3
    local info_url
    info_url="https://api.wordpress.org/themes/info/1.1/?action=theme_information"
    info_url="$info_url&request%5Bslug%5D=$slug"
    info_url="$info_url&request%5Bfields%5D%5Bversions%5D=1"
    info_url="$info_url&request%5Bfields%5D%5Btemplate%5D=1"
    local info_status=0
    if [ "$WP2SHELL_REFERENCE_JSON_TOOL" != "python3" ]; then
        reference_read_info_fields /dev/null
        WP2SHELL_REFERENCE_LAST_WARNING="Er is geen json-lezer beschikbaar, dus de gegevens van thema $slug zijn niet bij wordpress.org gecontroleerd voordat het pakket werd opgehaald."
        log_warn "$WP2SHELL_REFERENCE_LAST_WARNING"
    else
        reference_query_package_info "$info_url" "$version" "$work_dir" || info_status=$?
    fi
    case $info_status in
        0)
            if [ "$WP2SHELL_REFERENCE_INFO_VERSIONS_PRESENT" = "1" ] && [ "$WP2SHELL_REFERENCE_INFO_VERSION_KNOWN" != "1" ]; then
                reference_set_result "$REFERENCE_STATUS_NOT_IN_DIRECTORY" \
                    "Thema $slug staat wel in de directory maar versie $version is daar niet als uitgebrachte versie bekend. Er is geen origineel om mee te vergelijken."
                return 1
            fi
            ;;
        2)
            reference_set_result "$REFERENCE_STATUS_NOT_IN_DIRECTORY" \
                "Thema $slug komt niet voor in de officiele directory. Dat is de normale uitkomst bij een childthema, bij maatwerk en bij een premium thema, en betekent alleen dat er geen origineel is om mee te vergelijken."
            return 1
            ;;
        3)
            reference_set_result "$REFERENCE_STATUS_LOOKUP_FAILED" \
                "Het antwoord van wordpress.org over thema $slug kon niet gelezen worden. Dit thema is niet vergeleken."
            return 1
            ;;
        *)
            reference_set_result "$REFERENCE_STATUS_LOOKUP_FAILED" \
                "Het opvragen van de gegevens van thema $slug bij wordpress.org is mislukt. Dit thema is niet vergeleken."
            return 1
            ;;
    esac
    local zip_url="https://downloads.wordpress.org/theme/$slug.$version.zip"
    if [ -n "$WP2SHELL_REFERENCE_INFO_VERSION_URL" ] &&
        reference_url_is_official_download "$WP2SHELL_REFERENCE_INFO_VERSION_URL"; then
        zip_url=$WP2SHELL_REFERENCE_INFO_VERSION_URL
    fi
    if reference_download_and_build_manifest "$zip_url" "$work_dir" "$slug"; then
        WP2SHELL_REFERENCE_LAST_SOURCE="theme-zip"
        reference_set_result "$REFERENCE_STATUS_OBTAINED" \
            "Het officiele pakket van thema $slug versie $version is gedownload en uitgepakt. Voor themas bestaat geen checksum-service, dus het pakket zelf is de enige bron."
        return 0
    fi
    case $WP2SHELL_REFERENCE_DOWNLOAD_OUTCOME in
        notfound)
            reference_set_result "$REFERENCE_STATUS_NOT_IN_DIRECTORY" \
                "Van thema $slug is versie $version niet als pakket beschikbaar bij wordpress.org. Er is geen origineel om mee te vergelijken."
            ;;
        unsafe)
            reference_set_result "$REFERENCE_STATUS_UNSAFE_PACKAGE" \
                "Het opgehaalde pakket van thema $slug versie $version is door de veiligheidscontrole afgekeurd en niet gebruikt."
            ;;
        *)
            reference_set_result "$REFERENCE_STATUS_LOOKUP_FAILED" \
                "Het downloaden van thema $slug versie $version is mislukt. Dit thema is niet vergeleken."
            ;;
    esac
    return 1
}

reference_core_zip_url() {
    local version=$1 locale=$2
    if [ "$locale" = "en_US" ]; then
        printf 'https://downloads.wordpress.org/release/wordpress-%s.zip' "$version"
    else
        printf 'https://downloads.wordpress.org/release/%s/wordpress-%s.zip' "$locale" "$version"
    fi
    return 0
}

reference_fetch_core_checksums() {
    local version=$1 locale=$2 work_dir=$3
    local url="https://api.wordpress.org/core/checksums/1.0/?version=$version&locale=$locale"
    local body="$work_dir/core-checksums.json"
    if ! reference_http_get_body "$url" "$body"; then
        return 3
    fi
    local status=0
    reference_core_checksums_to_manifest "$body" "$work_dir/checksums-md5.tsv" || status=$?
    case $status in
        0)
            if reference_manifest_is_wellformed "$work_dir/checksums-md5.tsv" 32; then
                return 0
            fi
            return 3
            ;;
        4) return 1 ;;
        *) return 3 ;;
    esac
}

reference_fetch_core_package() {
    local version=$1 locale=$2 work_dir=$3
    local checksum_status=0 checksum_count=0
    reference_fetch_core_checksums "$version" "$locale" "$work_dir" || checksum_status=$?
    if [ "$checksum_status" -eq 1 ]; then
        reference_set_result "$REFERENCE_STATUS_NOT_IN_DIRECTORY" \
            "WordPress $version is voor taal $locale niet bekend bij de checksum-service van wordpress.org. Een onbekende versie en een onbekende taal zijn daar niet uit elkaar te houden, dus er is niets vergeleken."
        return 1
    fi
    if [ "$checksum_status" -eq 0 ]; then
        checksum_count=$(reference_manifest_line_count "$work_dir/checksums-md5.tsv")
        WP2SHELL_REFERENCE_LAST_MD5_MANIFEST="$work_dir/checksums-md5.tsv"
    else
        log_warn "De md5-checksums van WordPress $version voor taal $locale zijn niet opgehaald, het pakket wordt zonder die controle gebruikt"
    fi
    if [ "${WP2SHELL_REFERENCE_CORE_ZIP:-1}" != "1" ]; then
        if [ "$checksum_status" -eq 0 ]; then
            WP2SHELL_REFERENCE_LAST_SOURCE="core-checksums"
            reference_set_result "$REFERENCE_STATUS_CHECKSUMS_ONLY" \
                "Voor WordPress $version taal $locale zijn alleen de officiele md5-checksums opgehaald, want het downloaden van het core-pakket staat uit. Een sha256-manifest is er dus niet."
            return 1
        fi
        reference_set_result "$REFERENCE_STATUS_LOOKUP_FAILED" \
            "Voor WordPress $version taal $locale is niets opgehaald en het downloaden van het core-pakket staat uit. Er is niets vergeleken."
        return 1
    fi
    local zip_url
    zip_url=$(reference_core_zip_url "$version" "$locale")
    if reference_download_and_build_manifest "$zip_url" "$work_dir" "wordpress"; then
        WP2SHELL_REFERENCE_LAST_SOURCE="core-zip"
        local manifest_count
        manifest_count=$(reference_manifest_line_count "$work_dir/manifest.tsv")
        WP2SHELL_REFERENCE_LAST_ENTRY_COUNT=$manifest_count
        if [ "$checksum_status" -eq 0 ] && [ "$checksum_count" -ne "$manifest_count" ]; then
            WP2SHELL_REFERENCE_LAST_WARNING="Het core-pakket van versie $version taal $locale bevat $manifest_count bestanden terwijl de checksum-service er $checksum_count noemt. Taal of versie klopt dan mogelijk niet en een verschil mag niet als bewijs gelden."
            log_warn "$WP2SHELL_REFERENCE_LAST_WARNING"
        fi
        reference_set_result "$REFERENCE_STATUS_OBTAINED" \
            "Het officiele core-pakket van WordPress $version taal $locale is gedownload en uitgepakt, en het sha256-manifest is daaruit opgebouwd."
        return 0
    fi
    case $WP2SHELL_REFERENCE_DOWNLOAD_OUTCOME in
        notfound)
            reference_set_result "$REFERENCE_STATUS_NOT_IN_DIRECTORY" \
                "Het core-pakket van WordPress $version voor taal $locale bestaat niet bij wordpress.org. Er is niets vergeleken."
            ;;
        unsafe)
            reference_set_result "$REFERENCE_STATUS_UNSAFE_PACKAGE" \
                "Het opgehaalde core-pakket van WordPress $version taal $locale is door de veiligheidscontrole afgekeurd en niet gebruikt."
            ;;
        *)
            reference_set_result "$REFERENCE_STATUS_LOOKUP_FAILED" \
                "Het downloaden van het core-pakket van WordPress $version taal $locale is mislukt. Er is niets vergeleken."
            ;;
    esac
    return 1
}

reference_discard_work_dir() {
    local work_dir=$1
    if [ -z "$work_dir" ]; then
        return 0
    fi
    if ! path_is_within "$work_dir" "$(reference_cache_work_dir)"; then
        log_warn "Werkmap $work_dir ligt niet in de cache en wordt niet opgeruimd"
        return 1
    fi
    rm -rf -- "$work_dir"
    return 0
}

reference_store_result_in_cache() {
    local package_dir=$1 work_dir=$2 status=$3 detail=$4 warning=$5 source=$6
    local parent
    parent=$(dirname -- "$package_dir")
    if ! mkdir -p -- "$parent" 2>/dev/null; then
        return 1
    fi
    printf '%s\n' "$status" > "$work_dir/status"
    printf '%s\n' "$detail" > "$work_dir/detail"
    printf '%s\n' "$warning" > "$work_dir/warning"
    printf '%s\n' "$source" > "$work_dir/source"
    printf '%s\n' "$(timestamp_iso)" > "$work_dir/complete"
    rm -f -- "$work_dir/info.json" "$work_dir/info.fields" "$work_dir/checksums.json" "$work_dir/core-checksums.json"
    if mv -T -- "$work_dir" "$package_dir" 2>/dev/null; then
        return 0
    fi
    local existing=''
    existing=$(reference_read_first_line "$package_dir/status") || existing=''
    if [ "$status" = "$REFERENCE_STATUS_OBTAINED" ] && [ "$existing" != "$REFERENCE_STATUS_OBTAINED" ] &&
        path_is_within "$package_dir" "$(reference_cache_packages_dir)"; then
        log_debug "De bestaande cache-entry op $package_dir wordt vervangen door het volledige pakket"
        rm -rf -- "$package_dir"
        if mv -T -- "$work_dir" "$package_dir" 2>/dev/null; then
            return 0
        fi
    fi
    if [ -f "$package_dir/complete" ]; then
        log_debug "Een andere run heeft $package_dir al gevuld, de eigen werkmap wordt verwijderd"
        reference_discard_work_dir "$work_dir"
        return 0
    fi
    log_warn "Kan het opgehaalde pakket niet in de cache plaatsen op $package_dir"
    return 1
}

reference_read_first_line() {
    local source_file=$1 line=''
    if [ ! -f "$source_file" ]; then
        return 1
    fi
    IFS= read -r line < "$source_file" 2>/dev/null || true
    printf '%s' "$line"
    return 0
}

reference_read_cached_result() {
    local package_dir=$1
    if [ ! -f "$package_dir/complete" ]; then
        return 1
    fi
    local status='' detail='' warning='' source=''
    status=$(reference_read_first_line "$package_dir/status")
    detail=$(reference_read_first_line "$package_dir/detail")
    warning=$(reference_read_first_line "$package_dir/warning")
    source=$(reference_read_first_line "$package_dir/source")
    if [ -z "$status" ]; then
        return 1
    fi
    if [ "$status" = "$REFERENCE_STATUS_CHECKSUMS_ONLY" ] && [ "${WP2SHELL_REFERENCE_CORE_ZIP:-1}" = "1" ]; then
        log_debug "In de cache staan alleen de md5-checksums terwijl er nu wel een volledig pakket gevraagd wordt"
        return 1
    fi
    if [ "$status" = "$REFERENCE_STATUS_OBTAINED" ]; then
        if ! reference_manifest_is_wellformed "$package_dir/manifest.tsv" 64; then
            log_warn "Het manifest in de cache op $package_dir is onbruikbaar en wordt opnieuw opgehaald"
            return 1
        fi
        WP2SHELL_REFERENCE_LAST_MANIFEST="$package_dir/manifest.tsv"
        WP2SHELL_REFERENCE_LAST_ENTRY_COUNT=$(reference_manifest_line_count "$package_dir/manifest.tsv")
    fi
    if [ -f "$package_dir/checksums-md5.tsv" ]; then
        WP2SHELL_REFERENCE_LAST_MD5_MANIFEST="$package_dir/checksums-md5.tsv"
    fi
    WP2SHELL_REFERENCE_LAST_WARNING=$warning
    WP2SHELL_REFERENCE_LAST_SOURCE=$source
    reference_set_result "$status" "$detail"
    return 0
}

reference_memoize_result() {
    local key=$1
    WP2SHELL_REFERENCE_MEMO_STATUS["$key"]=$WP2SHELL_REFERENCE_LAST_STATUS
    WP2SHELL_REFERENCE_MEMO_MANIFEST["$key"]=$WP2SHELL_REFERENCE_LAST_MANIFEST
    WP2SHELL_REFERENCE_MEMO_DETAIL["$key"]=$WP2SHELL_REFERENCE_LAST_DETAIL
    WP2SHELL_REFERENCE_MEMO_WARNING["$key"]=$WP2SHELL_REFERENCE_LAST_WARNING
    return 0
}

reference_replay_memo() {
    local key=$1
    if [ -z "${WP2SHELL_REFERENCE_MEMO_STATUS[$key]+x}" ]; then
        return 1
    fi
    WP2SHELL_REFERENCE_LAST_MANIFEST=${WP2SHELL_REFERENCE_MEMO_MANIFEST["$key"]}
    WP2SHELL_REFERENCE_LAST_WARNING=${WP2SHELL_REFERENCE_MEMO_WARNING["$key"]}
    reference_set_result "${WP2SHELL_REFERENCE_MEMO_STATUS["$key"]}" "${WP2SHELL_REFERENCE_MEMO_DETAIL["$key"]}"
    return 0
}

reference_emit_manifest_path() {
    if [ "$WP2SHELL_REFERENCE_LAST_STATUS" != "$REFERENCE_STATUS_OBTAINED" ]; then
        return 1
    fi
    if [ -z "$WP2SHELL_REFERENCE_LAST_MANIFEST" ] || [ ! -s "$WP2SHELL_REFERENCE_LAST_MANIFEST" ]; then
        reference_set_result "$REFERENCE_STATUS_LOOKUP_FAILED" \
            "Het manifest is verdwenen tussen het ophalen en het gebruiken ervan. Er is niets vergeleken."
        return 1
    fi
    printf '%s' "$WP2SHELL_REFERENCE_LAST_MANIFEST"
    return 0
}

reference_manifest_for() {
    local rc=0
    reference_load_run_state || true
    reference_lookup_manifest "$@" || rc=$?
    reference_persist_run_state || log_debug "reference: de uitkomst kon niet weggeschreven worden"
    return "$rc"
}

reference_lookup_manifest() {
    local kind=${1:-} slug=${2:-} version=${3:-} locale=${4:-}
    reference_reset_last_result
    kind=${kind,,}
    if ! reference_kind_is_supported "$kind"; then
        reference_set_result "$REFERENCE_STATUS_UNSUPPORTED" \
            "Onbekend pakkettype ${kind:-leeg}. Alleen core, plugin en theme worden ondersteund."
        return 1
    fi
    if [ "$kind" = "core" ]; then
        if [ -z "$locale" ] && [ -n "$slug" ] && reference_locale_is_valid "$slug"; then
            locale=$slug
        fi
        if [ -z "$locale" ]; then
            locale=${WP2SHELL_REFERENCE_CORE_LOCALE:-en_US}
        fi
        slug=""
        if ! reference_locale_is_valid "$locale"; then
            reference_set_result "$REFERENCE_STATUS_UNSUPPORTED" \
                "De opgegeven taalcode is niet bruikbaar als referentie. Er is niets vergeleken."
            return 1
        fi
    else
        slug=${slug,,}
        locale=""
        if ! reference_slug_is_valid "$slug"; then
            reference_set_result "$REFERENCE_STATUS_UNSUPPORTED" \
                "De mapnaam is niet bruikbaar als slug voor wordpress.org, dus er is geen origineel opgevraagd."
            return 1
        fi
    fi
    if ! reference_version_is_valid "$version"; then
        reference_set_result "$REFERENCE_STATUS_UNSUPPORTED" \
            "Het versienummer ontbreekt of is niet bruikbaar als referentie. Een bewegend doel zoals trunk of latest wordt bewust geweigerd, want daarmee zou tegen de verkeerde versie vergeleken worden."
        return 1
    fi
    if ! reference_engine_available; then
        reference_set_result "$REFERENCE_STATUS_ENGINE_UNAVAILABLE" \
            "$WP2SHELL_REFERENCE_ENGINE_REASON"
        return 1
    fi
    local memo_key package_dir
    memo_key=$(reference_memo_key "$kind" "$slug" "$version" "$locale")
    package_dir=$(reference_package_directory "$kind" "$slug" "$version" "$locale")
    if reference_replay_memo "$memo_key"; then
        reference_emit_manifest_path
        return $?
    fi
    if reference_read_cached_result "$package_dir"; then
        reference_memoize_result "$memo_key"
        reference_emit_manifest_path
        return $?
    fi
    if ! reference_network_is_allowed; then
        reference_set_result "$REFERENCE_STATUS_OFFLINE_MISS" \
            "Dit pakket staat niet in de cache en de offline modus verbiedt netwerkverkeer. Er is niets vergeleken."
        reference_memoize_result "$memo_key"
        return 1
    fi
    local cap=${WP2SHELL_REFERENCE_MAX_FETCHES_PER_RUN:-60}
    case $cap in
        ''|*[!0-9]*) cap=60 ;;
    esac
    if [ "$WP2SHELL_REFERENCE_FETCH_COUNT" -ge "$cap" ]; then
        WP2SHELL_REFERENCE_CAP_REACHED=1
        reference_set_result "$REFERENCE_STATUS_CAP_REACHED" \
            "De limiet van $cap op te halen pakketten per run is bereikt, dus dit pakket is niet opgehaald en er is niets vergeleken."
        reference_memoize_result "$memo_key"
        return 1
    fi
    local work_dir
    work_dir=$(mktemp -d "$(reference_cache_work_dir)/package.XXXXXXXX" 2>/dev/null) || work_dir=''
    if [ -z "$work_dir" ]; then
        reference_set_result "$REFERENCE_STATUS_LOOKUP_FAILED" \
            "Er kon geen werkmap in de referentiecache aangemaakt worden. Er is niets vergeleken."
        return 1
    fi
    WP2SHELL_REFERENCE_FETCH_COUNT=$((WP2SHELL_REFERENCE_FETCH_COUNT + 1))
    local fetch_status=0
    case $kind in
        core) reference_fetch_core_package "$version" "$locale" "$work_dir" || fetch_status=$? ;;
        plugin) reference_fetch_plugin_package "$slug" "$version" "$work_dir" || fetch_status=$? ;;
        theme) reference_fetch_theme_package "$slug" "$version" "$work_dir" || fetch_status=$? ;;
    esac
    if [ "$fetch_status" -eq 0 ] || reference_status_is_cacheable "$WP2SHELL_REFERENCE_LAST_STATUS"; then
        if reference_store_result_in_cache "$package_dir" "$work_dir" \
            "$WP2SHELL_REFERENCE_LAST_STATUS" "$WP2SHELL_REFERENCE_LAST_DETAIL" \
            "$WP2SHELL_REFERENCE_LAST_WARNING" "$WP2SHELL_REFERENCE_LAST_SOURCE"; then
            if [ "$WP2SHELL_REFERENCE_LAST_STATUS" = "$REFERENCE_STATUS_OBTAINED" ]; then
                WP2SHELL_REFERENCE_LAST_MANIFEST="$package_dir/manifest.tsv"
                WP2SHELL_REFERENCE_LAST_ENTRY_COUNT=$(reference_manifest_line_count "$package_dir/manifest.tsv")
            fi
            if [ -f "$package_dir/checksums-md5.tsv" ]; then
                WP2SHELL_REFERENCE_LAST_MD5_MANIFEST="$package_dir/checksums-md5.tsv"
            fi
        else
            if [ "$WP2SHELL_REFERENCE_LAST_STATUS" = "$REFERENCE_STATUS_OBTAINED" ]; then
                reference_set_result "$REFERENCE_STATUS_LOOKUP_FAILED" \
                    "Het opgehaalde pakket kon niet in de cache geplaatst worden, daarom is er niets vergeleken."
            fi
            reference_discard_work_dir "$work_dir"
        fi
    else
        reference_discard_work_dir "$work_dir"
    fi
    reference_memoize_result "$memo_key"
    reference_emit_manifest_path
    return $?
}

reference_core_md5_manifest_for() {
    local version=${1:-} locale=${2:-}
    if [ -z "$locale" ]; then
        locale=${WP2SHELL_REFERENCE_CORE_LOCALE:-en_US}
    fi
    local manifest_status=0
    reference_manifest_for core "" "$version" "$locale" >/dev/null || manifest_status=$?
    reference_load_run_state || true
    if [ -n "$WP2SHELL_REFERENCE_LAST_MD5_MANIFEST" ] && [ -s "$WP2SHELL_REFERENCE_LAST_MD5_MANIFEST" ]; then
        printf '%s' "$WP2SHELL_REFERENCE_LAST_MD5_MANIFEST"
        return 0
    fi
    if [ "$manifest_status" -eq 0 ]; then
        reference_set_result "$REFERENCE_STATUS_LOOKUP_FAILED" \
            "Het sha256-manifest is er wel maar de officiele md5-checksums van deze core zijn niet beschikbaar."
        reference_persist_run_state || true
    fi
    return 1
}

reference_purge_expired() {
    local age=${WP2SHELL_REFERENCE_CACHE_MAX_AGE_DAYS:-30}
    case $age in
        ''|*[!0-9]*) age=30 ;;
    esac
    local packages work listing status=0 entry removed=0
    packages=$(reference_cache_packages_dir)
    work=$(reference_cache_work_dir)
    if [ ! -d "$packages" ] && [ ! -d "$work" ]; then
        return 0
    fi
    listing=$(mktemp -t wp2shell-reference-purge.XXXXXXXX) || return 1
    register_temp_cleanup "$listing"
    : > "$listing"
    if [ -d "$packages" ]; then
        "${WP2SHELL_FIND:-find}" -P "$packages" -mindepth 3 -maxdepth 3 -type d -mtime "+$age" -print0 \
            >> "$listing" 2>/dev/null || status=$?
    fi
    if [ -d "$work" ]; then
        "${WP2SHELL_FIND:-find}" -P "$work" -mindepth 1 -maxdepth 1 -type d -mtime +1 -print0 \
            >> "$listing" 2>/dev/null || status=$?
    fi
    local run_dir
    run_dir="$(reference_cache_root)/run"
    if [ -d "$run_dir" ]; then
        "${WP2SHELL_FIND:-find}" -P "$run_dir" -mindepth 1 -maxdepth 1 -type f -mtime +1 -print0 \
            >> "$listing" 2>/dev/null || status=$?
    fi
    if [ "$status" -ne 0 ]; then
        log_warn "Het opschonen van de referentiecache is niet volledig, exitcode $status"
    fi
    local cache_root
    cache_root=$(reference_cache_root)
    while IFS= read -r -d '' entry; do
        if ! path_is_within "$entry" "$cache_root"; then
            log_warn "Overgeslagen bij het opschonen omdat het pad buiten de cache valt: $entry"
            continue
        fi
        if rm -rf -- "$entry" 2>/dev/null; then
            removed=$((removed + 1))
        fi
    done < "$listing"
    rm -f -- "$listing"
    if [ "$removed" -gt 0 ]; then
        log_info "$removed verlopen pakketten uit de referentiecache verwijderd"
    fi
    WP2SHELL_REFERENCE_MEMO_STATUS=()
    WP2SHELL_REFERENCE_MEMO_MANIFEST=()
    WP2SHELL_REFERENCE_MEMO_DETAIL=()
    WP2SHELL_REFERENCE_MEMO_WARNING=()
    return 0
}
