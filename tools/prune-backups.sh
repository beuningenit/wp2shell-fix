#!/bin/bash
set -uo pipefail

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
. "$REPO_ROOT/lib/common.sh"

WP2SHELL_CONFIG_FILE=${WP2SHELL_CONFIG_FILE:-$REPO_ROOT/config/wp2shell.conf}
if [ -r "$WP2SHELL_CONFIG_FILE" ]; then
    . "$WP2SHELL_CONFIG_FILE"
else
    printf 'Configuratiebestand %s is niet leesbaar\n' "$WP2SHELL_CONFIG_FILE" >&2
    exit 2
fi

BACKUP_ROOT_MARKER=.wp2shell-backupboom
APPLY=0
KEEP=${WP2SHELL_BACKUP_KEEP_RUNS:-3}
BACKUP_ROOT=${WP2SHELL_BACKUP_DIR:-/var/backups/wp2shell}

while [ "$#" -gt 0 ]; do
    case $1 in
        --apply) APPLY=1 ;;
        --keep)
            shift
            KEEP=${1:-3}
            ;;
        --backup-dir)
            shift
            BACKUP_ROOT=${1:-$BACKUP_ROOT}
            ;;
        --help|-h)
            printf 'Gebruik: %s [--apply] [--keep <aantal>] [--backup-dir <pad>]\n\n' "$0"
            printf 'Zonder --apply wordt alleen getoond wat er zou gebeuren en verandert er\n'
            printf 'niets op de schijf.\n'
            printf 'Onvolledige backups, te herkennen aan een ontbrekende manifest.json,\n'
            printf 'hebben geen herstelwaarde en worden altijd als eerste aangewezen.\n'
            printf 'Van de runs met een herstelpunt blijven de %s nieuwste staan.\n' "$KEEP"
            exit 0
            ;;
        *)
            printf 'Onbekende optie: %s\n' "$1" >&2
            exit 2
            ;;
    esac
    shift
done

case $KEEP in
    ''|*[!0-9]*) KEEP=3 ;;
esac

if [ ! -d "$BACKUP_ROOT" ]; then
    printf 'Backupmap %s bestaat niet\n' "$BACKUP_ROOT" >&2
    exit 1
fi

backup_root_is_trustworthy() {
    local root=$1 resolved entry base depth
    resolved=$(cd -- "$root" 2>/dev/null && pwd -P) || return 1
    case $resolved in
        /|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/var)
            printf 'Weigering: %s is een systeemmap en nooit een backupboom\n' "$resolved" >&2
            return 1
            ;;
    esac
    depth=${resolved//[!\/]/}
    if [ "${#depth}" -lt 2 ]; then
        printf 'Weigering: %s ligt te hoog in de boom voor een backupmap\n' "$resolved" >&2
        return 1
    fi
    if [ -f "$resolved/$BACKUP_ROOT_MARKER" ]; then
        return 0
    fi
    local seen=0
    while IFS= read -r -d '' entry; do
        seen=1
        base=$(basename -- "$entry")
        case $base in
            [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]-*) : ;;
            *)
                printf 'Weigering: %s bevat %s, dat is geen runmap van deze toolkit\n' "$resolved" "$base" >&2
                printf 'Een backupboom bevat uitsluitend mappen met een run-id.\n' >&2
                return 1
                ;;
        esac
    done < <(find -P "$resolved" -mindepth 1 -maxdepth 1 -print0 2>/dev/null)
    if [ "$seen" = "0" ]; then
        printf 'Weigering: %s is leeg, er valt niets op te ruimen\n' "$resolved" >&2
        return 1
    fi
    return 0
}

if ! backup_root_is_trustworthy "$BACKUP_ROOT"; then
    printf 'Er is niets verwijderd.\n' >&2
    exit 2
fi

printf 'Backupmap : %s\n' "$BACKUP_ROOT"
printf 'Totaal    : %s\n' "$(du -sh -- "$BACKUP_ROOT" 2>/dev/null | cut -f1)"
printf 'Vrij      : %s\n' "$(df -Ph -- "$BACKUP_ROOT" 2>/dev/null | awk 'NR==2 {print $4}')"
if [ "$APPLY" = "1" ]; then
    printf 'Modus     : verwijderen\n\n'
else
    printf 'Modus     : alleen tonen, gebruik --apply om te verwijderen\n\n'
fi

reclaimed=0
removed=0
failures=0

directory_size_kilobytes() {
    local size
    size=$(du -sk -- "$1" 2>/dev/null | cut -f1) || size=0
    case $size in
        ''|*[!0-9]*) size=0 ;;
    esac
    printf '%s' "$size"
}

remove_directory() {
    local target=$1 label=$2 size
    size=$(directory_size_kilobytes "$target")
    printf '%-12s %6s MB  %s\n' "$label" "$((size / 1024))" "$target"
    if [ "$APPLY" != "1" ]; then
        reclaimed=$((reclaimed + size))
        removed=$((removed + 1))
        return 0
    fi
    if ! rm -rf -- "$target" 2>/dev/null; then
        printf '   VERWIJDEREN MISLUKT: %s\n' "$target" >&2
        failures=$((failures + 1))
        return 1
    fi
    reclaimed=$((reclaimed + size))
    removed=$((removed + 1))
    return 0
}

run_has_recovery_point() {
    find -P "$1" -mindepth 2 -maxdepth 2 -name manifest.json -type f -print -quit 2>/dev/null | grep -q .
}

ordered_runs=()
while IFS= read -r line; do
    if [ -n "$line" ]; then
        ordered_runs+=("$line")
    fi
done < <(
    while IFS= read -r -d '' candidate; do
        if run_has_recovery_point "$candidate"; then
            printf '%s %s\n' "$(stat -c '%Y' -- "$candidate" 2>/dev/null || printf '0')" "$candidate"
        fi
    done < <(find -P "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null) \
        | sort -rn | cut -d' ' -f2-
)

printf 'Onvolledige backups zonder herstelwaarde:\n'
found_incomplete=0
while IFS= read -r -d '' site_dir; do
    if [ -f "$site_dir/manifest.json" ]; then
        continue
    fi
    found_incomplete=1
    remove_directory "$site_dir" "onvolledig" || true
done < <(find -P "$BACKUP_ROOT" -mindepth 2 -maxdepth 2 -type d -print0 2>/dev/null)
if [ "$found_incomplete" = "0" ]; then
    printf '   geen\n'
fi

printf '\nVolledige backups, de %s nieuwste runs met een herstelpunt blijven staan:\n' "$KEEP"
index=0
found_old=0
for run_dir in ${ordered_runs[@]+"${ordered_runs[@]}"}; do
    index=$((index + 1))
    if [ "$index" -le "$KEEP" ]; then
        printf '%-12s %6s MB  %s\n' "behouden" "$(($(directory_size_kilobytes "$run_dir") / 1024))" "$run_dir"
        continue
    fi
    found_old=1
    remove_directory "$run_dir" "verouderd" || true
done
if [ "${#ordered_runs[@]}" -eq 0 ]; then
    printf '   let op: geen enkele run bevat een volledig herstelpunt\n'
elif [ "$found_old" = "0" ]; then
    printf '   geen verouderde runs\n'
fi

if [ "$APPLY" = "1" ]; then
    find -P "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -empty -delete 2>/dev/null || true
fi

printf '\n'
if [ "$APPLY" = "1" ]; then
    printf '%s mappen verwijderd, %s MB teruggewonnen\n' "$removed" "$((reclaimed / 1024))"
    printf 'Nu vrij: %s\n' "$(df -Ph -- "$BACKUP_ROOT" 2>/dev/null | awk 'NR==2 {print $4}')"
else
    printf '%s mappen zouden verwijderd worden, samen %s MB\n' "$removed" "$((reclaimed / 1024))"
    printf 'Draai opnieuw met --apply om dat daadwerkelijk te doen.\n'
fi

if [ "$failures" -gt 0 ]; then
    printf '%s mappen konden niet verwijderd worden\n' "$failures" >&2
    exit 1
fi
exit 0
