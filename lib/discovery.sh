WP2SHELL_DISCOVERY_LOADED=1

WP2SHELL_PRUNE_DIR_NAMES=(
    "node_modules"
    ".git"
    ".svn"
    ".wp-cli"
    "wp2shell-quarantine"
    "wp2shell-backup"
)

build_find_prune_arguments() {
    WP2SHELL_FIND_PRUNE_ARGS=()
    local name first=1
    WP2SHELL_FIND_PRUNE_ARGS+=('(')
    for name in "${WP2SHELL_PRUNE_DIR_NAMES[@]}"; do
        if [ "$first" = "1" ]; then
            first=0
        else
            WP2SHELL_FIND_PRUNE_ARGS+=(-o)
        fi
        WP2SHELL_FIND_PRUNE_ARGS+=(-name "$name")
    done
    WP2SHELL_FIND_PRUNE_ARGS+=(')' -prune -o)
    return 0
}

directadmin_is_present() {
    [ -d "${WP2SHELL_DIRECTADMIN_USERS_DIR:-/usr/local/directadmin/data/users}" ]
}

directadmin_user_list() {
    local users_dir=${WP2SHELL_DIRECTADMIN_USERS_DIR:-/usr/local/directadmin/data/users}
    if [ ! -d "$users_dir" ]; then
        return 1
    fi
    local entry
    for entry in "$users_dir"/*; do
        if [ -d "$entry" ]; then
            basename -- "$entry"
        fi
    done
    return 0
}

directadmin_domains_for_user() {
    local user=$1
    local users_dir=${WP2SHELL_DIRECTADMIN_USERS_DIR:-/usr/local/directadmin/data/users}
    local domains_file="$users_dir/$user/domains.list"
    if [ ! -r "$domains_file" ]; then
        return 1
    fi
    local line
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%%$'\r'}
        if [ -n "$line" ]; then
            printf '%s\n' "$line"
        fi
    done < "$domains_file"
    return 0
}

directadmin_user_from_path() {
    local candidate=$1
    local home_base=${WP2SHELL_HOME_BASE:-/home}
    case $candidate in
        "$home_base"/*)
            local remainder=${candidate#"$home_base"/}
            printf '%s' "${remainder%%/*}"
            return 0
            ;;
    esac
    return 1
}

domain_from_path() {
    local candidate=$1
    local home_base=${WP2SHELL_HOME_BASE:-/home}
    if [[ $candidate =~ ^"$home_base"/[^/]+/domains/([^/]+)(/|$) ]]; then
        printf '%s' "${BASH_REMATCH[1]}"
        return 0
    fi
    return 1
}

docroot_from_path() {
    local candidate=$1
    local home_base=${WP2SHELL_HOME_BASE:-/home}
    if [[ $candidate =~ ^("$home_base"/[^/]+/domains/[^/]+/(public_html|private_html)) ]]; then
        printf '%s' "${BASH_REMATCH[1]}"
        return 0
    fi
    return 1
}

relative_install_path() {
    local site_path=$1 docroot=$2
    if [ "$site_path" = "$docroot" ]; then
        printf '/'
        return 0
    fi
    case $site_path in
        "$docroot"/*)
            printf '/%s' "${site_path#"$docroot"/}"
            return 0
            ;;
    esac
    printf ''
    return 1
}

site_url_guess() {
    local domain=$1 relative=$2
    if [ -z "$domain" ]; then
        printf ''
        return 1
    fi
    if [ "$relative" = "/" ] || [ -z "$relative" ]; then
        printf 'https://%s/' "$domain"
        return 0
    fi
    printf 'https://%s%s/' "$domain" "$relative"
    return 0
}

softaculous_installations_file() {
    local candidate
    for candidate in \
        /usr/local/directadmin/plugins/softaculous/enduser/installations.php \
        /usr/local/softaculous/installations.php \
        /usr/local/directadmin/plugins/softaculous/soft.list
    do
        if [ -r "$candidate" ]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

softaculous_is_present() {
    [ -d /usr/local/softaculous ] || [ -d /usr/local/directadmin/plugins/softaculous ]
}

find_wordpress_roots_under() {
    local base=$1
    if [ ! -d "$base" ]; then
        return 0
    fi
    build_find_prune_arguments
    find -P "$base" "${WP2SHELL_FIND_PRUNE_ARGS[@]}" \
        -type f -path '*/wp-includes/version.php' -print0 2>/dev/null
    return 0
}

collect_search_bases() {
    WP2SHELL_SEARCH_BASES=()
    local glob expanded
    local -a matches
    for glob in "${WP2SHELL_DOCROOT_GLOBS[@]}"; do
        matches=()
        for expanded in $glob; do
            if [ -d "$expanded" ]; then
                matches+=("$expanded")
            fi
        done
        if [ "${#matches[@]}" -gt 0 ]; then
            WP2SHELL_SEARCH_BASES+=("${matches[@]}")
        fi
    done
    return 0
}

discover_sites() {
    local output_file=$1
    local restrict_site=${2:-}
    local restrict_user=${3:-}
    : > "$output_file"
    local -A seen_roots=()
    local -a candidate_files=()
    if [ -n "$restrict_site" ]; then
        if [ ! -d "$restrict_site" ]; then
            log_error "Opgegeven site bestaat niet: $restrict_site"
            return 1
        fi
        if [ -f "$restrict_site/wp-includes/version.php" ]; then
            candidate_files+=("$restrict_site/wp-includes/version.php")
        else
            while IFS= read -r -d '' found; do
                candidate_files+=("$found")
            done < <(find_wordpress_roots_under "$restrict_site")
        fi
    else
        collect_search_bases
        if [ "${#WP2SHELL_SEARCH_BASES[@]}" -eq 0 ]; then
            log_warn "Geen docroots gevonden onder de geconfigureerde paden"
            return 0
        fi
        local base
        for base in "${WP2SHELL_SEARCH_BASES[@]}"; do
            if [ -n "$restrict_user" ]; then
                local base_user
                base_user=$(directadmin_user_from_path "$base") || base_user=''
                if [ "$base_user" != "$restrict_user" ]; then
                    continue
                fi
            fi
            log_debug "Doorzoeken van $base"
            while IFS= read -r -d '' found; do
                candidate_files+=("$found")
            done < <(find_wordpress_roots_under "$base")
        done
    fi
    local version_file site_path resolved_path count=0
    for version_file in "${candidate_files[@]+"${candidate_files[@]}"}"; do
        site_path=${version_file%/wp-includes/version.php}
        if [ -z "$site_path" ] || [ ! -d "$site_path" ]; then
            continue
        fi
        resolved_path=$(readlink -f -- "$site_path" 2>/dev/null) || resolved_path="$site_path"
        if [ -n "${seen_roots[$resolved_path]:-}" ]; then
            log_debug "Dubbele installatie overgeslagen via symlink: $site_path"
            continue
        fi
        seen_roots[$resolved_path]=1
        if ! emit_site_record "$site_path" "$resolved_path" >> "$output_file"; then
            log_warn "Kon geen siterecord maken voor $site_path"
            continue
        fi
        count=$((count + 1))
    done
    log_info "Discovery voltooid, $count WordPress-installaties gevonden"
    return 0
}

emit_site_record() {
    local site_path=$1
    local resolved_path=$2
    local owner_user owner_group da_user domain docroot relative url
    owner_user=$(path_owner "$site_path") || owner_user=''
    owner_group=$(path_group "$site_path") || owner_group=''
    da_user=$(directadmin_user_from_path "$resolved_path") || da_user=''
    domain=$(domain_from_path "$resolved_path") || domain=''
    docroot=$(docroot_from_path "$resolved_path") || docroot=''
    relative=''
    if [ -n "$docroot" ]; then
        relative=$(relative_install_path "$resolved_path" "$docroot") || relative=''
    fi
    url=''
    if [ -n "$domain" ]; then
        url=$(site_url_guess "$domain" "$relative") || url=''
    fi
    local effective_user="$owner_user"
    if [ -z "$effective_user" ] || [ "$effective_user" = "root" ]; then
        if [ -n "$da_user" ] && user_exists "$da_user"; then
            effective_user="$da_user"
        fi
    fi
    local is_subinstall=0
    if [ -n "$relative" ] && [ "$relative" != "/" ]; then
        is_subinstall=1
    fi
    local root_owned=0
    if [ "$owner_user" = "root" ]; then
        root_owned=1
    fi
    printf '{'
    printf '"site_id":%s,' "$(json_string "$(site_identifier "$resolved_path")")"
    printf '"site_path":%s,' "$(json_string "$resolved_path")"
    printf '"discovered_path":%s,' "$(json_string "$site_path")"
    printf '"owner_user":%s,' "$(json_string "$owner_user")"
    printf '"owner_group":%s,' "$(json_string "$owner_group")"
    printf '"effective_user":%s,' "$(json_string "$effective_user")"
    printf '"directadmin_user":%s,' "$(json_string "$da_user")"
    printf '"domain":%s,' "$(json_string "$domain")"
    printf '"docroot":%s,' "$(json_string "$docroot")"
    printf '"relative_path":%s,' "$(json_string "$relative")"
    printf '"url":%s,' "$(json_string "$url")"
    printf '"is_subinstall":%s,' "$(json_bool "$is_subinstall")"
    printf '"root_owned":%s' "$(json_bool "$root_owned")"
    printf '}\n'
    return 0
}

site_record_field() {
    json_extract_field "$1" "$2"
}
