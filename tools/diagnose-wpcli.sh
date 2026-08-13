#!/bin/bash
set -uo pipefail

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
. "$REPO_ROOT/lib/common.sh"

if [ "$#" -lt 1 ]; then
    printf 'Gebruik: %s <pad-naar-docroot> [systeemgebruiker]\n' "$0" >&2
    exit 2
fi

SITE_PATH=$1
OWNER_USER=${2:-}

if [ -z "$OWNER_USER" ]; then
    OWNER_USER=$(stat -c '%U' -- "$SITE_PATH" 2>/dev/null) || OWNER_USER=''
fi
if [ -z "$OWNER_USER" ]; then
    printf 'Kon de eigenaar van %s niet bepalen, geef de gebruiker als tweede argument mee\n' "$SITE_PATH" >&2
    exit 2
fi

printf 'Site      : %s\n' "$SITE_PATH"
printf 'Gebruiker : %s\n' "$OWNER_USER"
printf 'Draait als: %s\n\n' "$(id -un)"

detect_optional_commands >/dev/null 2>&1

WORK_DIR=$(mktemp -d) || exit 1
trap 'rm -rf -- "$WORK_DIR"' EXIT INT TERM HUP

printf '1. sudo zonder wachtwoord naar %s\n' "$OWNER_USER"
if sudo -n -u "$OWNER_USER" true 2>"$WORK_DIR/sudo.err"; then
    printf '   in orde\n'
else
    printf '   MISLUKT: %s\n' "$(head -1 "$WORK_DIR/sudo.err")"
    printf '   Zonder dit kan de toolkit niets als de sitegebruiker doen.\n'
fi

printf '\n2. php in het pad van de sitegebruiker\n'
php_path=$(sudo -n -u "$OWNER_USER" env PATH=/usr/local/bin:/usr/bin:/bin sh -c 'command -v php' 2>/dev/null) || php_path=''
if [ -n "$php_path" ]; then
    printf '   gevonden op %s\n' "$php_path"
    printf '   versie: %s\n' "$(sudo -n -u "$OWNER_USER" env PATH=/usr/local/bin:/usr/bin:/bin php -r 'echo PHP_VERSION;' 2>&1 | head -1)"
else
    printf '   NIET GEVONDEN in /usr/local/bin:/usr/bin:/bin\n'
    printf '   De toolkit gebruikt bewust dat vaste pad, niet het pad van root.\n'
fi

printf '\n3. WP-CLI\n'
if ! ensure_wp_cli; then
    printf '   WP-CLI is niet beschikbaar en kon niet opgehaald worden\n'
    exit 1
fi
binary=$WP2SHELL_WP_CLI_RESOLVED
printf '   toolkit gebruikt: %s\n' "$binary"
printf '   rechten: %s\n' "$(stat -c '%A %U:%G' -- "$binary" 2>/dev/null)"
parent=$(dirname -- "$binary")
while [ "$parent" != "/" ] && [ -n "$parent" ]; do
    printf '   pad     : %s %s\n' "$(stat -c '%A' -- "$parent" 2>/dev/null)" "$parent"
    parent=$(dirname -- "$parent")
done
if sudo -n -u "$OWNER_USER" test -r "$binary" 2>/dev/null; then
    printf '   leesbaar voor %s: ja\n' "$OWNER_USER"
else
    printf '   leesbaar voor %s: NEE\n' "$OWNER_USER"
    printf '   Dit is de meest voorkomende oorzaak: het bestand staat in een map die de\n'
    printf '   sitegebruiker niet mag doorlopen.\n'
fi

printf '\n4. wp core is-installed, precies zoals de toolkit hem draait\n'
probe="$WORK_DIR/probe.out"
status=0
wp_is_functional "$OWNER_USER" "$SITE_PATH" "$probe" || status=$?
printf '   exitcode: %s\n' "$status"
if [ -s "$probe" ]; then
    printf '   uitvoer:\n'
    sed 's/^/     /' "$probe"
else
    printf '   geen uitvoer\n'
fi
if [ "$status" -ne 0 ]; then
    printf '   duiding: %s\n' "$(wp_probe_failure_reason "$probe" "$status")"
fi

if [ "$status" -eq 0 ]; then
    printf '\nWP-CLI werkt voor deze site. Een backup zou nu moeten slagen.\n'
    exit 0
fi
printf '\nWP-CLI werkt niet voor deze site. Zolang dit niet opgelost is slaat de toolkit\n'
printf 'deze site bij clean bewust over, want zonder databasebackup wordt er niet\n'
printf 'opgeschoond.\n'
exit 1
