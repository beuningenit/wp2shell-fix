#!/bin/bash
set -uo pipefail

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

TARGET_HOST=""
TARGET_PATH="/opt/wp2shell"
SSH_USER="root"
SSH_PORT="22"
INSTALL_CRON=0
CRON_SCHEDULE="17 3 * * *"
REPORT_EMAIL="support@beuningenit.nl"
DRY_RUN=0

PACKAGE_CONTENTS=(wp2shell.sh lib config tools tests README.md CLAUDE.md)
REQUIRED_COMMANDS=(php find grep tar sha1sum sha256sum curl flock base64)

usage() {
    cat <<'USAGE'
deploy.sh, installeert de wp2shell-toolkit

Gebruik:
  deploy.sh [opties]

Zonder opties installeert het script de toolkit op de machine waar je hem draait.
Draai hem dus gewoon op elke server apart. Geef alleen --host op wanneer je vanaf
deze machine naar een andere server wilt uitrollen.

Opties:
  --install-cron         Zet een dagelijkse read-only scan klaar in cron.
  --path <pad>           Installatiepad. Standaard /opt/wp2shell.
  --email <adres>        Adres voor de rapporten. Standaard support@beuningenit.nl.
  --schedule <cron>      Cron-schema voor de scan. Standaard "17 3 * * *".
  --dry-run              Toon wat er zou gebeuren zonder iets uit te voeren.
  --host <server>        Rol uit naar een andere server in plaats van deze.
  --user <gebruiker>     SSH-gebruiker bij --host. Standaard root.
  --port <poort>         SSH-poort bij --host. Standaard 22.
  --help                 Toon deze hulptekst.

Voorbeelden:
  ./deploy.sh --install-cron
  ./deploy.sh --install-cron --host web02.beuningenit.nl
USAGE
}

log() {
    printf '%s %s\n' "$(date '+%H:%M:%S')" "$*"
}

fail() {
    printf 'FOUT: %s\n' "$*" >&2
    exit 1
}

while [ "$#" -gt 0 ]; do
    case $1 in
        --host) shift; TARGET_HOST=${1:-} ;;
        --user) shift; SSH_USER=${1:-} ;;
        --port) shift; SSH_PORT=${1:-} ;;
        --path) shift; TARGET_PATH=${1:-} ;;
        --schedule) shift; CRON_SCHEDULE=${1:-} ;;
        --email) shift; REPORT_EMAIL=${1:-} ;;
        --install-cron) INSTALL_CRON=1 ;;
        --dry-run) DRY_RUN=1 ;;
        --help|-h) usage; exit 0 ;;
        *) fail "Onbekende optie: $1" ;;
    esac
    shift || true
done

case $TARGET_PATH in
    /*) ;;
    *) fail "--path moet een absoluut pad zijn" ;;
esac
case $TARGET_PATH in
    *[\'\"\\\ \$\`\;\&\|\<\>\(\)]*) fail "--path bevat tekens die niet zijn toegestaan" ;;
esac
case $REPORT_EMAIL in
    *[\'\"\\\ \$\`\;\&\|\<\>\(\)]*) fail "--email bevat tekens die niet zijn toegestaan" ;;
esac

verify_package_contents() {
    local missing=() entry
    for entry in "${PACKAGE_CONTENTS[@]}"; do
        if [ ! -e "$REPO_ROOT/$entry" ]; then
            missing+=("$entry")
        fi
    done
    if [ "${#missing[@]}" -eq 0 ]; then
        return 0
    fi
    printf 'FOUT: in %s ontbreken: %s\n' "$REPO_ROOT" "${missing[*]}" >&2
    printf 'deploy.sh werkt vanuit de map waarin het script zelf staat.\n' >&2
    printf 'Zet de hele repository neer en draai deploy.sh vanuit die map,\n' >&2
    printf 'bijvoorbeeld met: git clone https://github.com/BeuningenIT/wp2shell-fix.git\n' >&2
    printf 'Gebruik de https-url en niet de ssh-url, want die vraagt om een sleutel op deze server.\n' >&2
    exit 1
}

cron_file_content() {
    printf 'SHELL=/bin/bash\n'
    printf 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n'
    printf 'MAILTO=%s\n' "$REPORT_EMAIL"
    printf '%s root %s/wp2shell.sh scan --email %s >/dev/null 2>&1\n' \
        "$CRON_SCHEDULE" "$TARGET_PATH" "$REPORT_EMAIL"
}

report_missing_commands() {
    local missing=() command_name
    for command_name in "${REQUIRED_COMMANDS[@]}"; do
        if ! command -v "$command_name" >/dev/null 2>&1; then
            missing+=("$command_name")
        fi
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        printf '%s' "${missing[*]}"
    fi
    return 0
}

warn_about_non_gnu_find() {
    local find_binary=/usr/bin/find version_line
    version_line=$("$find_binary" --version 2>/dev/null | head -1) || version_line=''
    if [ "${version_line#*GNU findutils}" = "$version_line" ]; then
        printf 'LET OP: /usr/bin/find lijkt geen GNU findutils te zijn.\n' >&2
        printf 'De toolkit weigert dan te draaien, want de symlink-garanties hangen daarvan af.\n' >&2
    fi
    return 0
}

deploy_local() {
    log "Lokale installatie op $(hostname -f 2>/dev/null || hostname)"
    if [ "$(id -u)" != "0" ] && [ "$DRY_RUN" != "1" ]; then
        fail "Deze installatie moet als root draaien, want hij schrijft naar $TARGET_PATH en /var"
    fi
    local missing
    missing=$(report_missing_commands)
    if [ -n "$missing" ]; then
        fail "Op deze server ontbreken: $missing"
    fi
    warn_about_non_gnu_find

    local resolved_target
    resolved_target=$(readlink -f -- "$TARGET_PATH" 2>/dev/null) || resolved_target="$TARGET_PATH"
    if [ "$resolved_target" = "$REPO_ROOT" ]; then
        log "De repository staat al op $TARGET_PATH, kopieren is niet nodig"
    else
        if [ "$DRY_RUN" = "1" ]; then
            log "Zou de toolkit kopieren naar $TARGET_PATH"
        else
            mkdir -p -- "$TARGET_PATH" || fail "Kan $TARGET_PATH niet aanmaken"
            if ! tar --create --file=- --directory="$REPO_ROOT" \
                --exclude='.git' --exclude='reports/*' --exclude='*.tar.gz' \
                -- "${PACKAGE_CONTENTS[@]}" \
                | tar --extract --file=- --directory="$TARGET_PATH"; then
                fail "Kopieren naar $TARGET_PATH is mislukt"
            fi
            log "Toolkit geplaatst in $TARGET_PATH"
        fi
    fi

    if [ "$DRY_RUN" = "1" ]; then
        log "Zou rechten zetten en de werkmappen aanmaken"
    else
        chmod 0750 -- "$TARGET_PATH" 2>/dev/null || true
        chmod 0755 -- "$TARGET_PATH/wp2shell.sh" "$TARGET_PATH/tools/lint.sh" 2>/dev/null || true
        mkdir -p /var/lib/wp2shell /var/backups/wp2shell /var/log/wp2shell/reports \
            || fail "Kan de werkmappen onder /var niet aanmaken"
        chmod 0700 /var/lib/wp2shell /var/backups/wp2shell 2>/dev/null || true
        chmod 0750 /var/log/wp2shell /var/log/wp2shell/reports 2>/dev/null || true
    fi

    if [ "$DRY_RUN" != "1" ]; then
        if "$TARGET_PATH/wp2shell.sh" --help >/dev/null 2>&1; then
            log "De toolkit reageert"
        else
            fail "De toolkit start niet vanuit $TARGET_PATH"
        fi
    fi

    if [ "$INSTALL_CRON" = "1" ]; then
        if [ "$DRY_RUN" = "1" ]; then
            log "Zou /etc/cron.d/wp2shell schrijven:"
            cron_file_content
        else
            cron_file_content > /etc/cron.d/wp2shell || fail "Cron installeren is mislukt"
            chmod 0644 /etc/cron.d/wp2shell
            log "Cron staat in /etc/cron.d/wp2shell"
        fi
    fi

    log "Klaar. Draai nu eerst een read-only scan:"
    printf '  %s/wp2shell.sh scan\n' "$TARGET_PATH"
    return 0
}

deploy_remote() {
    case $TARGET_HOST in
        *[\'\"\\\ \$\`\;\&\|\<\>\(\)]*) fail "--host bevat tekens die niet zijn toegestaan" ;;
    esac
    case $SSH_PORT in
        ''|*[!0-9]*) fail "--port moet een getal zijn" ;;
    esac
    if ! command -v ssh >/dev/null 2>&1; then
        fail "ssh is niet beschikbaar"
    fi
    local ssh_target="$SSH_USER@$TARGET_HOST"
    local -a ssh_options=(-p "$SSH_PORT" -o BatchMode=yes -o StrictHostKeyChecking=accept-new)

    log "Toolkit inpakken vanuit $REPO_ROOT"
    local package
    package=$(mktemp -t wp2shell-deploy.XXXXXXXX.tar.gz)
    trap 'rm -f -- "$package"' EXIT
    if ! tar --create --gzip --file="$package" --directory="$REPO_ROOT" \
        --exclude='.git' --exclude='reports/*' --exclude='*.tar.gz' \
        -- "${PACKAGE_CONTENTS[@]}"; then
        fail "Inpakken is mislukt, zie de melding van tar hierboven"
    fi

    log "Verbinding controleren met $ssh_target"
    if [ "$DRY_RUN" != "1" ]; then
        ssh "${ssh_options[@]}" "$ssh_target" 'true' || fail "Kan niet inloggen op $TARGET_HOST"
        local remote_missing
        remote_missing=$(ssh "${ssh_options[@]}" "$ssh_target" \
            'for c in php find grep tar sha1sum sha256sum curl flock base64; do command -v $c >/dev/null 2>&1 || printf "%s " "$c"; done')
        if [ -n "$remote_missing" ]; then
            fail "Op $TARGET_HOST ontbreken: $remote_missing"
        fi
        if ! ssh "${ssh_options[@]}" "$ssh_target" \
            '/usr/bin/find --version 2>/dev/null | head -1 | grep -q "GNU findutils"'; then
            printf 'LET OP: /usr/bin/find op %s lijkt geen GNU findutils te zijn\n' "$TARGET_HOST" >&2
        fi
    fi

    log "Uitpakken naar $TARGET_PATH"
    if [ "$DRY_RUN" = "1" ]; then
        printf 'zou de toolkit uitpakken in %s op %s\n' "$TARGET_PATH" "$TARGET_HOST"
    else
        ssh "${ssh_options[@]}" "$ssh_target" "mkdir -p '$TARGET_PATH'" \
            || fail "Kan $TARGET_PATH niet aanmaken op $TARGET_HOST"
        ssh "${ssh_options[@]}" "$ssh_target" "tar --extract --gzip --directory='$TARGET_PATH'" < "$package" \
            || fail "Uitpakken op $TARGET_HOST is mislukt"
        ssh "${ssh_options[@]}" "$ssh_target" \
            "chmod 0750 '$TARGET_PATH' && chmod 0755 '$TARGET_PATH/wp2shell.sh' '$TARGET_PATH/tools/lint.sh'"
        ssh "${ssh_options[@]}" "$ssh_target" \
            'mkdir -p /var/lib/wp2shell /var/backups/wp2shell /var/log/wp2shell/reports && chmod 0700 /var/lib/wp2shell /var/backups/wp2shell && chmod 0750 /var/log/wp2shell /var/log/wp2shell/reports'
        if ssh "${ssh_options[@]}" "$ssh_target" "'$TARGET_PATH/wp2shell.sh' --help >/dev/null 2>&1"; then
            log "De toolkit reageert op $TARGET_HOST"
        else
            fail "De toolkit start niet op $TARGET_HOST"
        fi
    fi

    if [ "$INSTALL_CRON" = "1" ]; then
        if [ "$DRY_RUN" = "1" ]; then
            printf 'zou /etc/cron.d/wp2shell schrijven op %s:\n' "$TARGET_HOST"
            cron_file_content
        else
            cron_file_content | ssh "${ssh_options[@]}" "$ssh_target" \
                'cat > /etc/cron.d/wp2shell && chmod 0644 /etc/cron.d/wp2shell' \
                || fail "Cron installeren is mislukt"
            log "Cron staat in /etc/cron.d/wp2shell op $TARGET_HOST"
        fi
    fi

    log "Klaar. Draai op $TARGET_HOST eerst een read-only scan:"
    printf '  ssh %s -p %s %s/wp2shell.sh scan\n' "$ssh_target" "$SSH_PORT" "$TARGET_PATH"
    return 0
}

verify_package_contents

if [ -z "$TARGET_HOST" ]; then
    deploy_local
else
    deploy_remote
fi
