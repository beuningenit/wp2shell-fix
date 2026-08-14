#!/bin/bash
set -uo pipefail

REPO_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
. "$REPO_ROOT/lib/common.sh"
. "$REPO_ROOT/config/wp2shell.conf"
. "$REPO_ROOT/lib/quarantine.sh"
. "$REPO_ROOT/lib/backup.sh"

tests_run=0
tests_failed=0

expect_true() {
    local label=$1 status=$2
    tests_run=$((tests_run + 1))
    if [ "$status" = "0" ]; then
        printf 'ok   %s\n' "$label"
    else
        printf 'FAIL %s\n' "$label" >&2
        tests_failed=$((tests_failed + 1))
    fi
}

expect_equal() {
    local label=$1 expected=$2 actual=$3
    tests_run=$((tests_run + 1))
    if [ "$expected" = "$actual" ]; then
        printf 'ok   %s\n' "$label"
    else
        printf 'FAIL %s: verwacht "%s", kreeg "%s"\n' "$label" "$expected" "$actual" >&2
        tests_failed=$((tests_failed + 1))
    fi
}

WORKROOT=$(mktemp -d)
trap 'rm -rf -- "$WORKROOT"' EXIT

WP2SHELL_BACKUP_DIR="$WORKROOT/backups"
WP2SHELL_RUN_ID=testrun
WP2SHELL_FINDINGS_FILE="$WORKROOT/findings.ndjson"
: > "$WP2SHELL_FINDINGS_FILE"

SITE="$WORKROOT/home/klant/domains/a.nl/public_html"
mkdir -p "$SITE"
printf '<?php\n' > "$SITE/index.php"

backup_dir=$(backup_directory_for_site "$SITE")
prepare_backup_directory "$backup_dir" >/dev/null 2>&1
head -c 200000 /dev/zero > "$backup_dir/files.tar.gz"

expect_true "een onvolledige backup wordt opgeruimd" \
    "$(discard_incomplete_backup "$backup_dir" >/dev/null 2>&1 && printf 0 || printf 1)"
expect_equal "de map is daadwerkelijk verdwenen" "weg" \
    "$([ -d "$backup_dir" ] && printf 'aanwezig' || printf 'weg')"

prepare_backup_directory "$backup_dir" >/dev/null 2>&1
head -c 200000 /dev/zero > "$backup_dir/files.tar.gz"
printf '{}\n' > "$backup_dir/manifest.json"
discard_incomplete_backup "$backup_dir" >/dev/null 2>&1
expect_equal "een volledige backup blijft staan" "aanwezig" \
    "$([ -d "$backup_dir" ] && printf 'aanwezig' || printf 'weg')"

buiten="$WORKROOT/ergens-anders"
mkdir -p "$buiten"
discard_incomplete_backup "$buiten" >/dev/null 2>&1
expect_equal "een map buiten de backupboom wordt nooit verwijderd" "aanwezig" \
    "$([ -d "$buiten" ] && printf 'aanwezig' || printf 'weg')"

expect_equal "een ontbrekende map levert geen fout op" "0" \
    "$(discard_incomplete_backup "$WORKROOT/bestaat-niet" >/dev/null 2>&1; printf '%s' "$?")"

WP2SHELL_BACKUP_FREE_MARGIN_PERCENT=30
expect_true "een normale site komt door de ruimtecontrole" \
    "$(backup_space_is_sufficient "$SITE" "$WORKROOT" >/dev/null 2>&1 && printf 0 || printf 1)"

WP2SHELL_BACKUP_FREE_MARGIN_PERCENT=999999999
: > "$WP2SHELL_FINDINGS_FILE"
space_status=0
backup_space_is_sufficient "$SITE" "$WORKROOT" >/dev/null 2>&1 || space_status=$?
expect_equal "een onhaalbare marge blokkeert de backup" "1" "$space_status"
tests_run=$((tests_run + 1))
if grep -q '"category":"backup-space-insufficient"' "$WP2SHELL_FINDINGS_FILE"; then
    printf 'ok   het gebrek aan ruimte wordt als bevinding vastgelegd\n'
else
    printf 'FAIL het gebrek aan ruimte wordt niet gerapporteerd\n' >&2
    tests_failed=$((tests_failed + 1))
fi
WP2SHELL_BACKUP_FREE_MARGIN_PERCENT=30

PRUNE_ROOT="$WORKROOT/prune"
mkdir -p "$PRUNE_ROOT"
for run in 20260812-120000-1 20260813-120000-2; do
    for site in aaa bbb; do
        mkdir -p "$PRUNE_ROOT/$run/$site"
        head -c 100000 /dev/zero > "$PRUNE_ROOT/$run/$site/files.tar.gz"
    done
done
printf '{}\n' > "$PRUNE_ROOT/20260812-120000-1/aaa/manifest.json"
for run in 20260812-120000-1 20260813-120000-2; do
    printf '{"tool":"wp2shell"}\n' > "$PRUNE_ROOT/$run/.wp2shell-run"
done

CONF="$WORKROOT/prune.conf"
sed "s|^WP2SHELL_BACKUP_DIR=.*|WP2SHELL_BACKUP_DIR=\"$PRUNE_ROOT\"|" "$REPO_ROOT/config/wp2shell.conf" > "$CONF"

WP2SHELL_CONFIG_FILE="$CONF" "$REPO_ROOT/tools/prune-backups.sh" --lock-file "$WORKROOT/test.lock" >/dev/null 2>&1
expect_equal "zonder --apply wordt er niets verwijderd" "4" \
    "$(find "$PRUNE_ROOT" -mindepth 2 -maxdepth 2 -type d | wc -l | tr -d ' ')"

WP2SHELL_CONFIG_FILE="$CONF" "$REPO_ROOT/tools/prune-backups.sh" --apply --lock-file "$WORKROOT/test.lock" >/dev/null 2>&1
expect_equal "met --apply blijven alleen de herstelpunten over" "1" \
    "$(find "$PRUNE_ROOT" -mindepth 2 -maxdepth 2 -type d | wc -l | tr -d ' ')"
expect_equal "het herstelpunt zelf is bewaard" "1" \
    "$(find "$PRUNE_ROOT" -name manifest.json -type f | wc -l | tr -d ' ')"

ORDER_ROOT="$WORKROOT/volgorde"
mkdir -p "$ORDER_ROOT/20260801-120000-1/site1" "$ORDER_ROOT/20260801-120000-1/site-onvolledig" "$ORDER_ROOT/20260813-120000-2/site1"
printf '{}\n' > "$ORDER_ROOT/20260801-120000-1/site1/manifest.json"
printf '{}\n' > "$ORDER_ROOT/20260813-120000-2/site1/manifest.json"
head -c 1000 /dev/zero > "$ORDER_ROOT/20260801-120000-1/site-onvolledig/files.tar.gz"
printf '{"tool":"wp2shell"}\n' > "$ORDER_ROOT/20260801-120000-1/.wp2shell-run"
printf '{"tool":"wp2shell"}\n' > "$ORDER_ROOT/20260813-120000-2/.wp2shell-run"
touch -d '2026-08-01' "$ORDER_ROOT/20260801-120000-1"
touch -d '2026-08-13' "$ORDER_ROOT/20260813-120000-2"
ORDER_CONF="$WORKROOT/volgorde.conf"
sed "s|^WP2SHELL_BACKUP_DIR=.*|WP2SHELL_BACKUP_DIR=\"$ORDER_ROOT\"|" "$REPO_ROOT/config/wp2shell.conf" > "$ORDER_CONF"
WP2SHELL_CONFIG_FILE="$ORDER_CONF" "$REPO_ROOT/tools/prune-backups.sh" --apply --keep 1 --lock-file "$WORKROOT/test.lock" >/dev/null 2>&1
expect_equal "de nieuwste run met een herstelpunt overleeft het opruimen" "aanwezig" \
    "$([ -d "$ORDER_ROOT/20260813-120000-2" ] && printf 'aanwezig' || printf 'weg')"
expect_equal "de oudere run wordt wel opgeruimd" "weg" \
    "$([ -d "$ORDER_ROOT/20260801-120000-1" ] && printf 'aanwezig' || printf 'weg')"

DRY_ROOT="$WORKROOT/droog"
mkdir -p "$DRY_ROOT/20260813-120000-9" "$DRY_ROOT/20260813-120000-1/site1"
printf '{}\n' > "$DRY_ROOT/20260813-120000-1/site1/manifest.json"
printf '{"tool":"wp2shell"}\n' > "$DRY_ROOT/20260813-120000-1/.wp2shell-run"
printf '{"tool":"wp2shell"}\n' > "$DRY_ROOT/20260813-120000-9/.wp2shell-run"
DRY_CONF="$WORKROOT/droog.conf"
sed "s|^WP2SHELL_BACKUP_DIR=.*|WP2SHELL_BACKUP_DIR=\"$DRY_ROOT\"|" "$REPO_ROOT/config/wp2shell.conf" > "$DRY_CONF"
voor=$(find "$DRY_ROOT" | LC_ALL=C sort)
WP2SHELL_CONFIG_FILE="$DRY_CONF" "$REPO_ROOT/tools/prune-backups.sh" --lock-file "$WORKROOT/test.lock" >/dev/null 2>&1
na=$(find "$DRY_ROOT" | LC_ALL=C sort)
expect_equal "zonder --apply verandert er niets op de schijf, ook geen lege runmap" "$voor" "$na"

FAIL_ROOT="$WORKROOT/onverwijderbaar"
mkdir -p "$FAIL_ROOT/20260813-120000-1/site-onvolledig"
head -c 100 /dev/zero > "$FAIL_ROOT/20260813-120000-1/site-onvolledig/files.tar.gz"
printf '{"tool":"wp2shell"}\n' > "$FAIL_ROOT/20260813-120000-1/.wp2shell-run"
FAIL_CONF="$WORKROOT/onverwijderbaar.conf"
sed "s|^WP2SHELL_BACKUP_DIR=.*|WP2SHELL_BACKUP_DIR=\"$FAIL_ROOT\"|" "$REPO_ROOT/config/wp2shell.conf" > "$FAIL_CONF"
SHIM_DIR="$WORKROOT/shim"
mkdir -p "$SHIM_DIR"
cat > "$SHIM_DIR/rm" <<'SHIMEOF'
#!/bin/bash
exit 1
SHIMEOF
chmod 0755 -- "$SHIM_DIR/rm"
fail_status=0
PATH="$SHIM_DIR:$PATH" WP2SHELL_CONFIG_FILE="$FAIL_CONF" \
    "$REPO_ROOT/tools/prune-backups.sh" --apply --lock-file "$WORKROOT/test.lock" >/dev/null 2>&1 || fail_status=$?
expect_equal "een mislukte verwijdering geeft een exitcode die niet nul is" "1" "$fail_status"
expect_equal "de map die niet verwijderd kon worden staat er nog" "aanwezig" \
    "$([ -d "$FAIL_ROOT/20260813-120000-1/site-onvolledig" ] && printf 'aanwezig' || printf 'weg')"

UNSAFE_CONF="$WORKROOT/onveilig.conf"
sed "s|^WP2SHELL_BACKUP_DIR=.*|WP2SHELL_BACKUP_DIR=\"/\"|" "$REPO_ROOT/config/wp2shell.conf" > "$UNSAFE_CONF"
unsafe_status=0
WP2SHELL_CONFIG_FILE="$UNSAFE_CONF" "$REPO_ROOT/tools/prune-backups.sh" --apply --lock-file "$WORKROOT/test.lock" >/dev/null 2>&1 || unsafe_status=$?
expect_equal "de hoofdmap wordt geweigerd als backupboom" "2" "$unsafe_status"

VREEMD_ROOT="$WORKROOT/vreemde-boom"
mkdir -p "$VREEMD_ROOT/klantdata"
VREEMD_CONF="$WORKROOT/vreemd.conf"
sed "s|^WP2SHELL_BACKUP_DIR=.*|WP2SHELL_BACKUP_DIR=\"$VREEMD_ROOT\"|" "$REPO_ROOT/config/wp2shell.conf" > "$VREEMD_CONF"
vreemd_status=0
WP2SHELL_CONFIG_FILE="$VREEMD_CONF" "$REPO_ROOT/tools/prune-backups.sh" --apply --lock-file "$WORKROOT/test.lock" >/dev/null 2>&1 || vreemd_status=$?
expect_equal "een map zonder runmappen wordt geweigerd" "2" "$vreemd_status"

ONBEREIKBAAR_CONF="$WORKROOT/onbereikbaar.conf"
sed "s|^WP2SHELL_BACKUP_DIR=.*|WP2SHELL_BACKUP_DIR=\"$PRUNE_ROOT\"|" "$REPO_ROOT/config/wp2shell.conf" > "$ONBEREIKBAAR_CONF"
slot_status=0
WP2SHELL_CONFIG_FILE="$ONBEREIKBAAR_CONF" \
    "$REPO_ROOT/tools/prune-backups.sh" --apply --lock-file "$WORKROOT/bestaat-niet/slot" >/dev/null 2>&1 || slot_status=$?
expect_equal "een onbereikbaar vergrendelingsbestand blokkeert het opruimen" "3" "$slot_status"
expect_equal "de vreemde inhoud is onaangeroerd" "aanwezig" \
    "$([ -d "$VREEMD_ROOT/klantdata" ] && printf 'aanwezig' || printf 'weg')"

MARKER_ROOT="$WORKROOT/gedeelde-backupmap"
mkdir -p "$MARKER_ROOT/20260813-120000-1/site1" "$MARKER_ROOT/backup-van-iemand-anders"
printf '{}\n' > "$MARKER_ROOT/20260813-120000-1/site1/manifest.json"
printf '{"tool":"wp2shell"}\n' > "$MARKER_ROOT/20260813-120000-1/.wp2shell-run"
printf 'kostbaar\n' > "$MARKER_ROOT/backup-van-iemand-anders/data.sql"
printf 'markering\n' > "$MARKER_ROOT/.wp2shell-backupboom"
MARKER_CONF="$WORKROOT/gedeeld.conf"
sed "s|^WP2SHELL_BACKUP_DIR=.*|WP2SHELL_BACKUP_DIR=\"$MARKER_ROOT\"|" "$REPO_ROOT/config/wp2shell.conf" > "$MARKER_CONF"
marker_status=0
WP2SHELL_LOCK_FILE="$WORKROOT/prune.lock" WP2SHELL_CONFIG_FILE="$MARKER_CONF" \
    "$REPO_ROOT/tools/prune-backups.sh" --apply --lock-file "$WORKROOT/test.lock" >/dev/null 2>&1 || marker_status=$?
expect_equal "een markeringsbestand alleen maakt een gedeelde map nog geen backupboom" "2" "$marker_status"
expect_equal "de backup van een ander is onaangeroerd" "aanwezig" \
    "$([ -f "$MARKER_ROOT/backup-van-iemand-anders/data.sql" ] && printf 'aanwezig' || printf 'weg')"

LOCK_ROOT="$WORKROOT/vergrendeld"
mkdir -p "$LOCK_ROOT/20260813-120000-1/site-onvolledig"
head -c 100 /dev/zero > "$LOCK_ROOT/20260813-120000-1/site-onvolledig/files.tar.gz"
printf '{"tool":"wp2shell"}\n' > "$LOCK_ROOT/20260813-120000-1/.wp2shell-run"
LOCK_CONF="$WORKROOT/vergrendeld.conf"
sed "s|^WP2SHELL_BACKUP_DIR=.*|WP2SHELL_BACKUP_DIR=\"$LOCK_ROOT\"|" "$REPO_ROOT/config/wp2shell.conf" > "$LOCK_CONF"
LOCK_FILE="$WORKROOT/actieve-run.lock"
: > "$LOCK_FILE"
lock_status=0
if command -v flock >/dev/null 2>&1; then
    exec 7>"$LOCK_FILE"
    flock -n 7
    WP2SHELL_CONFIG_FILE="$LOCK_CONF" \
        "$REPO_ROOT/tools/prune-backups.sh" --apply --lock-file "$LOCK_FILE" >/dev/null 2>&1 || lock_status=$?
    flock -u 7
    exec 7>&-
    expect_equal "opruimen tijdens een lopende run wordt geweigerd" "3" "$lock_status"
    expect_equal "de backup van de lopende run staat er nog" "aanwezig" \
        "$([ -d "$LOCK_ROOT/20260813-120000-1/site-onvolledig" ] && printf 'aanwezig' || printf 'weg')"
    lock_status=0
    WP2SHELL_CONFIG_FILE="$LOCK_CONF" \
        "$REPO_ROOT/tools/prune-backups.sh" --apply --lock-file "$LOCK_FILE" >/dev/null 2>&1 || lock_status=$?
    expect_equal "zonder lopende run mag het opruimen wel" "0" "$lock_status"
fi

RESERVE_STATE="$WORKROOT/reservering"
mkdir -p "$RESERVE_STATE"
(
    WP2SHELL_STATE_DIR="$RESERVE_STATE"
    beschikbaar=$(backup_available_kilobytes "$WORKROOT")
    helft=$((beschikbaar * 60 / 100))
    eerste=1
    tweede=1
    WP2SHELL_BACKUP_RESERVED_KILOBYTES=0
    backup_reserve_space "$helft" "$WORKROOT" >/dev/null 2>&1 && eerste=0
    (
        WP2SHELL_BACKUP_RESERVED_KILOBYTES=0
        backup_reserve_space "$helft" "$WORKROOT" >/dev/null 2>&1
    ) && tweede=0
    printf '%s %s\n' "$eerste" "$tweede" > "$RESERVE_STATE/uitkomst"
    backup_release_space
    printf '%s\n' "$(cat "$(backup_reservation_file)" 2>/dev/null || printf 'leeg')" > "$RESERVE_STATE/na-vrijgave"
)
read -r eerste tweede < "$RESERVE_STATE/uitkomst"
expect_equal "de eerste worker krijgt zijn ruimte gereserveerd" "0" "$eerste"
expect_equal "de tweede worker wordt geweigerd omdat de ruimte al vergeven is" "1" "$tweede"
expect_equal "na vrijgave staat het grootboek weer op nul" "0" \
    "$(cat "$RESERVE_STATE/na-vrijgave")"

BEWIJS_ROOT="$WORKROOT/herkomst"
mkdir -p "$BEWIJS_ROOT/20260813-120000-vreemd/klantdata" "$BEWIJS_ROOT/20260813-120000-1/site1"
printf 'kostbaar\n' > "$BEWIJS_ROOT/20260813-120000-vreemd/klantdata/data.sql"
printf '{"tool":"wp2shell","run_id":"x"}\n' > "$BEWIJS_ROOT/20260813-120000-1/.wp2shell-run"
head -c 1000 /dev/zero > "$BEWIJS_ROOT/20260813-120000-1/site1/files.tar.gz"
BEWIJS_CONF="$WORKROOT/herkomst.conf"
sed "s|^WP2SHELL_BACKUP_DIR=.*|WP2SHELL_BACKUP_DIR=\"$BEWIJS_ROOT\"|" "$REPO_ROOT/config/wp2shell.conf" > "$BEWIJS_CONF"
WP2SHELL_CONFIG_FILE="$BEWIJS_CONF" "$REPO_ROOT/tools/prune-backups.sh" --apply --lock-file "$WORKROOT/test.lock" >/dev/null 2>&1
expect_equal "een runmap zonder herkomstbewijs blijft onaangeroerd" "aanwezig" \
    "$([ -f "$BEWIJS_ROOT/20260813-120000-vreemd/klantdata/data.sql" ] && printf 'aanwezig' || printf 'weg')"
expect_equal "een runmap met markering wordt wel opgeruimd" "weg" \
    "$([ -d "$BEWIJS_ROOT/20260813-120000-1/site1" ] && printf 'aanwezig' || printf 'weg')"

MARKERING_ROOT="$WORKROOT/markering"
(
    WP2SHELL_BACKUP_DIR="$MARKERING_ROOT"
    WP2SHELL_RUN_ID=20260814-090000-77
    prepare_backup_directory "$(backup_directory_for_site "$SITE")" >/dev/null 2>&1
)
expect_equal "de backup-engine legt een runmarkering aan" "aanwezig" \
    "$([ -f "$MARKERING_ROOT/20260814-090000-77/.wp2shell-run" ] && printf 'aanwezig' || printf 'weg')"

STALE_STATE="$WORKROOT/blijfhangen"
mkdir -p "$STALE_STATE"
(
    WP2SHELL_STATE_DIR="$STALE_STATE"
    printf '999999999\n' > "$(backup_reservation_file)"
    backup_reset_reservations
    printf '%s\n' "$(cat "$(backup_reservation_file)")" > "$STALE_STATE/na-reset"
)
expect_equal "een blijven hangen reservering wordt bij een nieuwe run gewist" "0" \
    "$(cat "$STALE_STATE/na-reset")"

printf '%s tests, %s mislukt\n' "$tests_run" "$tests_failed"
if [ "$tests_failed" -gt 0 ]; then
    exit 1
fi
exit 0
