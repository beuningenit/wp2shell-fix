WP2SHELL_VERSION_LOADED=1

WP2SHELL_STATUS_RCE_VULNERABLE=rce-vulnerable
WP2SHELL_STATUS_SQLI_LATENT=sqli-latent
WP2SHELL_STATUS_PATCHED=patched
WP2SHELL_STATUS_NOT_AFFECTED=not-affected
WP2SHELL_STATUS_UNKNOWN=unknown

WP2SHELL_SECURITY_CURRENT=current
WP2SHELL_SECURITY_OUTDATED=outdated
WP2SHELL_SECURITY_UNSUPPORTED=unsupported
WP2SHELL_SECURITY_UNKNOWN=unknown

WP2SHELL_LOWEST_AFFECTED_BRANCH="6.8"
WP2SHELL_HIGHEST_KNOWN_BRANCH="7.1"

wp_version_normalize() {
    local raw=$1
    if [[ $raw =~ ^([0-9]+(\.[0-9]+){0,2}(-([Aa]lpha|[Bb]eta|[Rr][Cc])[0-9.-]*)?) ]]; then
        printf '%s' "${BASH_REMATCH[1]}"
        return 0
    fi
    return 1
}

wp_version_branch() {
    local version=$1
    if [[ $version =~ ^([0-9]+)\.([0-9]+) ]]; then
        printf '%s.%s' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
        return 0
    fi
    if [[ $version =~ ^([0-9]+) ]]; then
        printf '%s.0' "${BASH_REMATCH[1]}"
        return 0
    fi
    return 1
}

version_at_least() {
    php -r 'exit(version_compare($argv[1], $argv[2], ">=") ? 0 : 1);' "$1" "$2" 2>/dev/null
}

version_less_than() {
    php -r 'exit(version_compare($argv[1], $argv[2], "<") ? 0 : 1);' "$1" "$2" 2>/dev/null
}

wp_version_from_disk() {
    local site_path=$1
    local version_file="$site_path/wp-includes/version.php"
    if [ ! -r "$version_file" ]; then
        return 1
    fi
    local line raw
    line=$(grep -m1 -E '^[[:space:]]*\$wp_version[[:space:]]*=' -- "$version_file" 2>/dev/null) || return 1
    if [[ $line =~ \$wp_version[[:space:]]*=[[:space:]]*[\'\"]([^\'\"]+)[\'\"] ]]; then
        raw=${BASH_REMATCH[1]}
        wp_version_normalize "$raw"
        return $?
    fi
    return 1
}

wp_db_version_from_disk() {
    local site_path=$1
    local version_file="$site_path/wp-includes/version.php"
    if [ ! -r "$version_file" ]; then
        return 1
    fi
    local line
    line=$(grep -m1 -E '^[[:space:]]*\$wp_db_version[[:space:]]*=' -- "$version_file" 2>/dev/null) || return 1
    if [[ $line =~ \$wp_db_version[[:space:]]*=[[:space:]]*([0-9]+) ]]; then
        printf '%s' "${BASH_REMATCH[1]}"
        return 0
    fi
    return 1
}

classify_wp2shell_status() {
    local version=$1
    local branch
    if ! branch=$(wp_version_branch "$version"); then
        printf '%s' "$WP2SHELL_STATUS_UNKNOWN"
        return 0
    fi
    local minimum=${WP2SHELL_WP2SHELL_PATCHED_MIN[$branch]:-}
    if [ -z "$minimum" ]; then
        if version_less_than "$version" "$WP2SHELL_LOWEST_AFFECTED_BRANCH"; then
            printf '%s' "$WP2SHELL_STATUS_NOT_AFFECTED"
            return 0
        fi
        if version_at_least "$version" "$WP2SHELL_HIGHEST_KNOWN_BRANCH"; then
            printf '%s' "$WP2SHELL_STATUS_PATCHED"
            return 0
        fi
        printf '%s' "$WP2SHELL_STATUS_UNKNOWN"
        return 0
    fi
    if version_at_least "$version" "$minimum"; then
        printf '%s' "$WP2SHELL_STATUS_PATCHED"
        return 0
    fi
    if [ -n "${WP2SHELL_RCE_CHAIN_BRANCHES[$branch]:-}" ]; then
        printf '%s' "$WP2SHELL_STATUS_RCE_VULNERABLE"
        return 0
    fi
    printf '%s' "$WP2SHELL_STATUS_SQLI_LATENT"
    return 0
}

classify_current_security_status() {
    local version=$1
    local branch
    if ! branch=$(wp_version_branch "$version"); then
        printf '%s' "$WP2SHELL_SECURITY_UNKNOWN"
        return 0
    fi
    local minimum=${WP2SHELL_CURRENT_SECURITY_MIN[$branch]:-}
    if [ -z "$minimum" ]; then
        if version_less_than "$version" "4.7"; then
            printf '%s' "$WP2SHELL_SECURITY_UNSUPPORTED"
            return 0
        fi
        printf '%s' "$WP2SHELL_SECURITY_UNKNOWN"
        return 0
    fi
    if version_at_least "$version" "$minimum"; then
        printf '%s' "$WP2SHELL_SECURITY_CURRENT"
        return 0
    fi
    printf '%s' "$WP2SHELL_SECURITY_OUTDATED"
    return 0
}

recommended_target_version() {
    local version=$1
    local branch
    if ! branch=$(wp_version_branch "$version"); then
        printf ''
        return 1
    fi
    local target=${WP2SHELL_CURRENT_SECURITY_MIN[$branch]:-}
    if [ -n "$target" ]; then
        printf '%s' "$target"
        return 0
    fi
    printf ''
    return 1
}

wp2shell_status_dutch_label() {
    case $1 in
        "$WP2SHELL_STATUS_RCE_VULNERABLE")
            printf 'kwetsbaar voor de volledige wp2shell RCE-keten' ;;
        "$WP2SHELL_STATUS_SQLI_LATENT")
            printf 'kwetsbaar voor de SQL-injectie, alleen misbruikbaar via een plugin of thema' ;;
        "$WP2SHELL_STATUS_PATCHED")
            printf 'gepatcht tegen wp2shell' ;;
        "$WP2SHELL_STATUS_NOT_AFFECTED")
            printf 'niet geraakt door wp2shell, versie is ouder dan 6.8' ;;
        *)
            printf 'onbekende versie, handmatige review nodig' ;;
    esac
}

security_status_dutch_label() {
    case $1 in
        "$WP2SHELL_SECURITY_CURRENT")
            printf 'draait de actuele securityrelease' ;;
        "$WP2SHELL_SECURITY_OUTDATED")
            printf 'mist de securityrelease van 6 augustus 2026' ;;
        "$WP2SHELL_SECURITY_UNSUPPORTED")
            printf 'draait een versie die geen security-updates meer krijgt' ;;
        *)
            printf 'securitystatus onbekend' ;;
    esac
}

severity_for_wp2shell_status() {
    case $1 in
        "$WP2SHELL_STATUS_RCE_VULNERABLE") printf '%s' "$SEVERITY_CRITICAL" ;;
        "$WP2SHELL_STATUS_SQLI_LATENT") printf '%s' "$SEVERITY_HIGH" ;;
        "$WP2SHELL_STATUS_UNKNOWN") printf '%s' "$SEVERITY_MEDIUM" ;;
        *) printf '%s' "$SEVERITY_INFO" ;;
    esac
}

branch_was_in_exposure_window() {
    local version=$1
    local branch
    if ! branch=$(wp_version_branch "$version"); then
        return 1
    fi
    if [ -n "${WP2SHELL_RCE_CHAIN_BRANCHES[$branch]:-}" ]; then
        return 0
    fi
    return 1
}

evaluate_site_version() {
    local site_path=$1
    WP2SHELL_SITE_VERSION=''
    WP2SHELL_SITE_DB_VERSION=''
    WP2SHELL_SITE_BRANCH=''
    WP2SHELL_SITE_WP2SHELL_STATUS="$WP2SHELL_STATUS_UNKNOWN"
    WP2SHELL_SITE_SECURITY_STATUS="$WP2SHELL_SECURITY_UNKNOWN"
    WP2SHELL_SITE_TARGET_VERSION=''
    local version
    if ! version=$(wp_version_from_disk "$site_path"); then
        return 1
    fi
    WP2SHELL_SITE_VERSION="$version"
    WP2SHELL_SITE_DB_VERSION=$(wp_db_version_from_disk "$site_path") || WP2SHELL_SITE_DB_VERSION=''
    WP2SHELL_SITE_BRANCH=$(wp_version_branch "$version") || WP2SHELL_SITE_BRANCH=''
    WP2SHELL_SITE_WP2SHELL_STATUS=$(classify_wp2shell_status "$version")
    WP2SHELL_SITE_SECURITY_STATUS=$(classify_current_security_status "$version")
    WP2SHELL_SITE_TARGET_VERSION=$(recommended_target_version "$version") || WP2SHELL_SITE_TARGET_VERSION=''
    return 0
}
