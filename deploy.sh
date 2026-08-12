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

usage() {
    cat <<'USAGE'
deploy.sh, rolt de wp2shell-toolkit uit naar een server

Gebruik:
  deploy.sh --host <server> [opties]

Opties:
  --host <server>        Doelserver, verplicht.
  --user <gebruiker>     SSH-gebruiker. Standaard root.
  --port <poort>         SSH-poort. Standaard 22.
  --path <pad>           Installatiepad op de server. Standaard /opt/wp2shell.
  --install-cron         Zet een dagelijkse read-only scan klaar in cron.
  --schedule <cron>      Cron-schema voor de scan. Standaard "17 3 * * *".
  --email <adres>        Adres voor de rapporten. Standaard support@beuningenit.nl.
  --dry-run              Toon wat er zou gebeuren zonder iets uit te voeren.
  --help                 Toon deze hulptekst.

De toolkit draait per server. Voer dit script uit voor elke machine apart.

Voorbeeld:
  ./deploy.sh --host web01.beuningenit.nl --install-cron
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

if [ -z "$TARGET_HOST" ]; then
    usage
    exit 1
fi

if ! command -v ssh >/dev/null 2>&1; then
    fail "ssh is niet beschikbaar"
fi

case $TARGET_PATH in
    /*) ;;
    *) fail "--path moet een absoluut pad zijn" ;;
esac
case $TARGET_PATH in
    *[\'\"\\\ \$\`\;\&\|\<\>\(\)]*) fail "--path bevat tekens die niet zijn toegestaan" ;;
esac
case $TARGET_HOST in
    *[\'\"\\\ \$\`\;\&\|\<\>\(\)]*) fail "--host bevat tekens die niet zijn toegestaan" ;;
esac
case $SSH_PORT in
    ''|*[!0-9]*) fail "--port moet een getal zijn" ;;
esac
case $REPORT_EMAIL in
    *[\'\"\\\ \$\`\;\&\|\<\>\(\)]*) fail "--email bevat tekens die niet zijn toegestaan" ;;
esac

SSH_TARGET="$SSH_USER@$TARGET_HOST"
SSH_OPTIONS=(-p "$SSH_PORT" -o BatchMode=yes -o StrictHostKeyChecking=accept-new)

run_remote() {
    if [ "$DRY_RUN" = "1" ]; then
        printf 'zou uitvoeren op %s: %s\n' "$TARGET_HOST" "$*"
        return 0
    fi
    ssh "${SSH_OPTIONS[@]}" "$SSH_TARGET" "$@"
}

log "Toolkit inpakken"
PACKAGE=$(mktemp -t wp2shell-deploy.XXXXXXXX.tar.gz)
trap 'rm -f -- "$PACKAGE"' EXIT

tar --create --gzip --file="$PACKAGE" \
    --directory="$REPO_ROOT" \
    --exclude='.git' \
    --exclude='reports/*' \
    --exclude='*.tar.gz' \
    wp2shell.sh lib config tools tests README.md CLAUDE.md 2>/dev/null \
    || fail "Inpakken is mislukt"

log "Verbinding controleren met $SSH_TARGET"
if [ "$DRY_RUN" != "1" ]; then
    ssh "${SSH_OPTIONS[@]}" "$SSH_TARGET" 'true' || fail "Kan niet inloggen op $TARGET_HOST"
fi

log "Voorwaarden controleren op de server"
if [ "$DRY_RUN" != "1" ]; then
    MISSING=$(ssh "${SSH_OPTIONS[@]}" "$SSH_TARGET" \
        'for c in php find grep tar sha1sum sha256sum curl flock base64; do command -v $c >/dev/null 2>&1 || printf "%s " "$c"; done')
    if [ -n "$MISSING" ]; then
        fail "Op $TARGET_HOST ontbreken: $MISSING"
    fi
    if ! ssh "${SSH_OPTIONS[@]}" "$SSH_TARGET" '/usr/bin/find --version 2>/dev/null | head -1 | grep -q "GNU findutils"'; then
        printf 'LET OP: /usr/bin/find op %s lijkt geen GNU findutils te zijn\n' "$TARGET_HOST" >&2
    fi
fi

log "Uitpakken naar $TARGET_PATH"
run_remote "mkdir -p '$TARGET_PATH'" || fail "Kan $TARGET_PATH niet aanmaken"

if [ "$DRY_RUN" != "1" ]; then
    ssh "${SSH_OPTIONS[@]}" "$SSH_TARGET" "tar --extract --gzip --directory='$TARGET_PATH'" < "$PACKAGE" \
        || fail "Uitpakken op de server is mislukt"
fi

run_remote "chmod 0750 '$TARGET_PATH' && chmod 0755 '$TARGET_PATH/wp2shell.sh' '$TARGET_PATH/tools/lint.sh'"
run_remote "mkdir -p /var/lib/wp2shell /var/backups/wp2shell /var/log/wp2shell/reports"
run_remote "chmod 0700 /var/lib/wp2shell /var/backups/wp2shell && chmod 0750 /var/log/wp2shell /var/log/wp2shell/reports"

log "Installatie controleren"
if [ "$DRY_RUN" != "1" ]; then
    if ssh "${SSH_OPTIONS[@]}" "$SSH_TARGET" "'$TARGET_PATH/wp2shell.sh' --help >/dev/null 2>&1"; then
        log "De toolkit reageert op $TARGET_HOST"
    else
        fail "De toolkit start niet op $TARGET_HOST"
    fi
fi

if [ "$INSTALL_CRON" = "1" ]; then
    log "Cron installeren voor de doorlopende scan"
    CRON_FILE="/etc/cron.d/wp2shell"
    CRON_CONTENT="SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MAILTO=$REPORT_EMAIL
$CRON_SCHEDULE root $TARGET_PATH/wp2shell.sh scan --email $REPORT_EMAIL >/dev/null 2>&1
"
    if [ "$DRY_RUN" = "1" ]; then
        printf 'zou schrijven naar %s op %s:\n%s\n' "$CRON_FILE" "$TARGET_HOST" "$CRON_CONTENT"
    else
        printf '%s' "$CRON_CONTENT" | ssh "${SSH_OPTIONS[@]}" "$SSH_TARGET" \
            'cat > /etc/cron.d/wp2shell && chmod 0644 /etc/cron.d/wp2shell' \
            || fail "Cron installeren is mislukt"
        log "Cron staat in $CRON_FILE"
    fi
fi

log "Klaar. Draai op $TARGET_HOST eerst een read-only scan:"
printf '  ssh %s -p %s %s scan\n' "$SSH_TARGET" "$SSH_PORT" "$TARGET_PATH/wp2shell.sh"
