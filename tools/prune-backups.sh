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

APPLY=0
KEEP=${WP2SHELL_BACKUP_KEEP_RUNS:-3}
BACKUP_ROOT=${WP2SHELL_BACKUP_DIR:-/var/backups/wp2shell}
LOCK_FILE=${WP2SHELL_LOCK_FILE:-/var/run/wp2shell.lock}

require_value() {
    local option=$1 value=${2:-}
    case $value in
        ''|--*)
            printf 'De optie %s heeft een waarde nodig\n' "$option" >&2
            exit 2
            ;;
    esac
    printf '%s' "$value"
    return 0
}

while [ "$#" -gt 0 ]; do
    case $1 in
        --apply) APPLY=1 ;;
        --keep)
            KEEP=$(require_value --keep "${2:-}") || exit 2
            shift
            ;;
        --backup-dir)
            BACKUP_ROOT=$(require_value --backup-dir "${2:-}") || exit 2
            shift
            ;;
        --lock-file)
            LOCK_FILE=$(require_value --lock-file "${2:-}") || exit 2
            shift
            ;;
        --help|-h)
            printf 'Gebruik: %s [--apply] [--keep <aantal>] [--backup-dir <pad>] [--lock-file <pad>]\n\n' "$0"
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
    ''|*[!0-9]*)
        printf 'De optie --keep verwacht een geheel getal, niet %s\n' "$KEEP" >&2
        exit 2
        ;;
esac
if [ "${#KEEP}" -gt 4 ] || [ "$KEEP" -lt 1 ]; then
    printf 'De optie --keep verwacht een getal tussen 1 en 9999, niet %s\n' "$KEEP" >&2
    exit 2
fi
if [ "${#BACKUP_ROOT}" -lt 2 ]; then
    printf 'Het pad naar de backupmap is te kort: %s\n' "$BACKUP_ROOT" >&2
    exit 2
fi

if [ ! -d "$BACKUP_ROOT" ]; then
    printf 'Backupmap %s bestaat niet\n' "$BACKUP_ROOT" >&2
    exit 1
fi

for benodigd in tar gzip du df find stat grep sed mktemp; do
    if ! command -v "$benodigd" >/dev/null 2>&1; then
        printf 'Het commando %s ontbreekt. Zonder dat commando is niet vast te stellen of\n' "$benodigd" >&2
        printf 'een backup bruikbaar is, en dan zou elke backup als onbruikbaar gelden en\n' >&2
        printf 'verwijderd worden. Er is niets verwijderd.\n' >&2
        exit 2
    fi
done

archiefcontrole_werkt() {
    local proefmap resultaat=0
    proefmap=$(mktemp -d) || return 1
    mkdir -p -- "$proefmap/inhoud" 2>/dev/null || resultaat=1
    printf 'proef\n' > "$proefmap/inhoud/bestand" 2>/dev/null || resultaat=1
    if [ "$resultaat" -eq 0 ]; then
        tar --create --gzip --file="$proefmap/proef.tar.gz" --directory="$proefmap" inhoud 2>/dev/null || resultaat=1
    fi
    if [ "$resultaat" -eq 0 ]; then
        tar --list --file="$proefmap/proef.tar.gz" >/dev/null 2>&1 || resultaat=1
    fi
    rm -rf -- "$proefmap" 2>/dev/null || true
    return "$resultaat"
}

if ! archiefcontrole_werkt; then
    printf 'Een zelfgemaakt proefarchief kon niet gelezen worden, dus tar of gzip werkt hier\n' >&2
    printf 'niet naar behoren. Elke geldige backup zou dan als onbruikbaar gelden en\n' >&2
    printf 'verwijderd worden. Er is niets verwijderd.\n' >&2
    exit 2
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
    local seen=0
    while IFS= read -r -d '' entry; do
        seen=1
        base=$(basename -- "$entry")
        if [ ! -d "$entry" ]; then
            continue
        fi
        if [ -f "$entry/.wp2shell-run" ] && grep -q '"tool":"wp2shell"' -- "$entry/.wp2shell-run" 2>/dev/null; then
            continue
        fi
        case $base in
            [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]-*) : ;;
            *)
                printf 'Weigering: %s bevat %s, dat is geen runmap van deze toolkit\n' "$resolved" "$base" >&2
                printf 'Een backupboom bevat uitsluitend runmappen met een markering of een run-id.\n' >&2
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

PRUNE_LOCK=$LOCK_FILE
if ! lock_path_is_acceptable "$PRUNE_LOCK"; then
    printf 'Er is niets verwijderd.\n' >&2
    exit 2
fi
if ! exec 9>>"$PRUNE_LOCK" 2>/dev/null; then
    printf 'Het vergrendelingsbestand %s kan niet geopend worden, dus er valt niet vast\n' "$PRUNE_LOCK" >&2
    printf 'te stellen of er een wp2shell-run draait. Opruimen tijdens een lopende backup\n' >&2
    printf 'kan een backup verwijderen die op dat moment geschreven wordt. Er is niets\n' >&2
    printf 'verwijderd.\n' >&2
    exit 3
fi
if command -v flock >/dev/null 2>&1; then
    if ! flock -n 9; then
        printf 'Er draait een wp2shell-run, opruimen tijdens een lopende backup kan een\n' >&2
        printf 'backup verwijderen die op dat moment geschreven wordt. Er is niets\n' >&2
        printf 'verwijderd. Probeer het opnieuw als de run klaar is.\n' >&2
        exit 3
    fi
else
    printf 'flock ontbreekt, er kan niet vastgesteld worden of er een run draait.\n' >&2
    printf 'Er is niets verwijderd.\n' >&2
    exit 3
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

run_name_looks_like_run_id() {
    case $(basename -- "$1") in
        [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9]-*) return 0 ;;
    esac
    return 1
}

normaliseer_tijdsleutel() {
    local ruw=$1 cijfers
    cijfers=${ruw//[!0-9]/}
    if [ "${#cijfers}" -lt 14 ]; then
        while [ "${#cijfers}" -lt 14 ]; do
            cijfers="${cijfers}0"
        done
    fi
    printf '%s' "${cijfers:0:14}"
    return 0
}

run_sort_key() {
    local run_dir=$1 stempel='' naam
    if [ -f "$run_dir/.wp2shell-run" ]; then
        stempel=$(sed -n 's/.*"created_at":"\([^"]*\)".*/\1/p' -- "$run_dir/.wp2shell-run" 2>/dev/null | head -1) || stempel=''
    fi
    if [ -n "$stempel" ]; then
        normaliseer_tijdsleutel "$stempel"
        return 0
    fi
    naam=$(basename -- "$run_dir")
    if run_name_looks_like_run_id "$run_dir"; then
        normaliseer_tijdsleutel "${naam%%-*}${naam#*-}"
        return 0
    fi
    printf '%s' "00000000000000"
    return 0
}

run_is_ours() {
    local run_dir=$1 manifest
    if [ -f "$run_dir/.wp2shell-run" ] && grep -q '"tool":"wp2shell"' -- "$run_dir/.wp2shell-run" 2>/dev/null; then
        return 0
    fi
    if ! run_name_looks_like_run_id "$run_dir"; then
        return 1
    fi
    while IFS= read -r -d '' manifest; do
        if grep -q '"files_archive_sha256"' -- "$manifest" 2>/dev/null; then
            return 0
        fi
    done < <(find -P "$run_dir" -mindepth 2 -maxdepth 2 -name manifest.json -type f -print0 2>/dev/null)
    return 1
}

manifest_recorded_number() {
    local manifest=$1 key=$2 value
    value=$(sed -n "s/.*\"$key\":\([0-9]*\).*/\1/p" -- "$manifest" 2>/dev/null | head -1) || value=''
    case $value in
        ''|*[!0-9]*) return 1 ;;
    esac
    printf '%s' "$value"
    return 0
}

file_size_or_zero() {
    local size
    size=$(stat -c '%s' -- "$1" 2>/dev/null) || size=0
    case $size in
        ''|*[!0-9]*) size=0 ;;
    esac
    printf '%s' "$size"
    return 0
}

manifest_is_complete() {
    local manifest=$1 site_dir archive dump recorded actual
    if [ ! -s "$manifest" ]; then
        return 1
    fi
    case $(tail -c 2 -- "$manifest" 2>/dev/null) in
        '}'|'}'*) : ;;
        *) return 1 ;;
    esac
    if ! grep -q '"database_dump_bytes"' -- "$manifest" 2>/dev/null; then
        return 1
    fi
    site_dir=$(dirname -- "$manifest")
    archive="$site_dir/files.tar.gz"
    dump="$site_dir/database.sql"
    if [ ! -s "$archive" ] || [ ! -s "$dump" ]; then
        return 1
    fi
    if recorded=$(manifest_recorded_number "$manifest" files_archive_bytes); then
        actual=$(file_size_or_zero "$archive")
        if [ "$recorded" != "$actual" ]; then
            return 1
        fi
    fi
    if recorded=$(manifest_recorded_number "$manifest" database_dump_bytes); then
        actual=$(file_size_or_zero "$dump")
        if [ "$recorded" != "$actual" ]; then
            return 1
        fi
    fi
    if ! grep -q -m1 -i 'CREATE TABLE' -- "$dump" 2>/dev/null; then
        return 1
    fi
    if ! tar --list --file="$archive" >/dev/null 2>&1; then
        return 1
    fi
    return 0
}

site_has_recovery_point() {
    manifest_is_complete "$1/manifest.json"
}

run_has_recovery_point() {
    local site_dir
    while IFS= read -r -d '' site_dir; do
        if site_has_recovery_point "$site_dir"; then
            return 0
        fi
    done < <(find -P "$1" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)
    return 1
}

geldige_punten=()
while IFS= read -r line; do
    if [ -n "$line" ]; then
        geldige_punten+=("$line")
    fi
done < <(
    while IFS= read -r -d '' run_dir; do
        if ! run_is_ours "$run_dir"; then
            continue
        fi
        while IFS= read -r -d '' site_dir; do
            if site_has_recovery_point "$site_dir"; then
                printf '%s\t%s\t%s\n' "$(basename -- "$site_dir")" "$(run_sort_key "$run_dir")" "$site_dir"
            fi
        done < <(find -P "$run_dir" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)
    done < <(find -P "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)
)

printf 'Onvolledige backups zonder herstelwaarde:\n'
found_incomplete=0
while IFS= read -r -d '' site_dir; do
    if site_has_recovery_point "$site_dir"; then
        continue
    fi
    found_incomplete=1
    remove_directory "$site_dir" "onvolledig" || true
done < <(
    while IFS= read -r -d '' run_dir; do
        if ! run_is_ours "$run_dir"; then
            continue
        fi
        find -P "$run_dir" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null
    done < <(find -P "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)
)
if [ "$found_incomplete" = "0" ]; then
    printf '   geen\n'
fi

printf '\nHerstelpunten, per site blijven de %s nieuwste staan:\n' "$KEEP"
found_old=0
huidige_site=''
teller=0
while IFS=$'\t' read -r site_id run_id site_dir; do
    if [ -z "$site_id" ]; then
        continue
    fi
    if [ "$site_id" != "$huidige_site" ]; then
        huidige_site=$site_id
        teller=0
    fi
    teller=$((teller + 1))
    if [ "$teller" -le "$KEEP" ]; then
        printf '%-12s %6s MB  %s\n' "behouden" "$(($(directory_size_kilobytes "$site_dir") / 1024))" "$site_dir"
        continue
    fi
    found_old=1
    remove_directory "$site_dir" "verouderd" || true
done < <(printf '%s\n' ${geldige_punten[@]+"${geldige_punten[@]}"} | LC_ALL=C sort -t"$(printf '\t')" -k1,1 -k2,2r)
if [ "${#geldige_punten[@]}" -eq 0 ]; then
    printf '   let op: er is geen enkel volledig herstelpunt gevonden\n'
elif [ "$found_old" = "0" ]; then
    printf '   geen verouderde herstelpunten\n'
fi

if [ "$APPLY" = "1" ]; then
    while IFS= read -r -d '' run_dir; do
        if ! run_is_ours "$run_dir"; then
            continue
        fi
        if find -P "$run_dir" -mindepth 1 -maxdepth 1 -type d -print -quit 2>/dev/null | grep -q .; then
            continue
        fi
        rm -f -- "$run_dir/.wp2shell-run" 2>/dev/null || true
        rmdir -- "$run_dir" 2>/dev/null || true
    done < <(find -P "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null)
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
