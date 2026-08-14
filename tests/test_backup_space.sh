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

schrijf_herstelpunt() {
    local site_dir=$1 archief_bytes dump_bytes
    mkdir -p -- "$site_dir"
    mkdir -p -- "$site_dir/inhoud"
    printf 'inhoud van een site\n' > "$site_dir/inhoud/index.php"
    tar --create --gzip --file="$site_dir/files.tar.gz" --directory="$site_dir" inhoud 2>/dev/null
    rm -rf -- "$site_dir/inhoud"
    printf 'CREATE TABLE wp_options (id int);\n' > "$site_dir/database.sql"
    archief_bytes=$(stat -c '%s' -- "$site_dir/files.tar.gz")
    dump_bytes=$(stat -c '%s' -- "$site_dir/database.sql")
    printf '{"run_id":"x","files_archive_sha256":"aa","files_archive_bytes":%s,"database_dump_bytes":%s}\n' \
        "$archief_bytes" "$dump_bytes" > "$site_dir/manifest.json"
    return 0
}

WORKROOT=$(mktemp -d)
trap 'rm -rf -- "$WORKROOT"' EXIT

WP2SHELL_BACKUP_DIR="$WORKROOT/backups"
WP2SHELL_STATE_DIR="$WORKROOT/state"
mkdir -p "$WP2SHELL_STATE_DIR"
WP2SHELL_RUN_ID=testrun
WP2SHELL_FINDINGS_FILE="$WORKROOT/findings.ndjson"
: > "$WP2SHELL_FINDINGS_FILE"

DFSHIM="$WORKROOT/dfshim"
mkdir -p "$DFSHIM"
cat > "$DFSHIM/df" <<'DFEOF'
#!/bin/bash
printf 'Filesystem 1024-blocks Used Available Capacity Mounted\n'
printf '/dev/nep 1000 999 1 100%% /\n'
DFEOF
chmod 0755 -- "$DFSHIM/df"

DBSTUB="$WORKROOT/wp-dbsize"
cat > "$DBSTUB" <<'DBEOF'
#!/bin/bash
case " $* " in
    *" db size "*) printf '1048576\n'; exit 0 ;;
esac
exit 0
DBEOF
chmod 0755 -- "$DBSTUB"
WP2SHELL_WP_CLI_RESOLVED="$DBSTUB"
EIGENAAR=$(id -un)

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
printf '{"database_dump_bytes":1}\n' > "$backup_dir/manifest.json"
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
    "$(backup_space_is_sufficient "$SITE" "$WORKROOT" "$EIGENAAR" >/dev/null 2>&1 && printf 0 || printf 1)"

: > "$WP2SHELL_FINDINGS_FILE"
space_status=0
(
    PATH="$DFSHIM:$PATH"
    backup_space_is_sufficient "$SITE" "$WORKROOT" "$EIGENAAR" >/dev/null 2>&1
) || space_status=$?
expect_equal "een schijf die vol is blokkeert de backup" "1" "$space_status"
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
schrijf_herstelpunt "$PRUNE_ROOT/20260812-120000-1/aaa"
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
schrijf_herstelpunt "$ORDER_ROOT/20260801-120000-1/site1"
schrijf_herstelpunt "$ORDER_ROOT/20260813-120000-2/site1"
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
schrijf_herstelpunt "$DRY_ROOT/20260813-120000-1/site1"
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
schrijf_herstelpunt "$MARKER_ROOT/20260813-120000-1/site1"
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
mkdir -p "$WORKROOT/worker-a" "$WORKROOT/worker-b" "$WORKROOT/worker-c"
(
    WP2SHELL_STATE_DIR="$RESERVE_STATE"
    backup_reset_reservations
    beschikbaar=$(backup_available_kilobytes "$WORKROOT")
    helft=$((beschikbaar * 60 / 100))
    eerste=1
    tweede=1
    backup_reserve_space "$helft" "$WORKROOT/worker-a" >/dev/null 2>&1 && eerste=0
    (
        WP2SHELL_BACKUP_RESERVED_DIRECTORY=""
        backup_reserve_space "$helft" "$WORKROOT/worker-b" >/dev/null 2>&1
    ) && tweede=0
    printf '%s %s\n' "$eerste" "$tweede" > "$RESERVE_STATE/uitkomst"
    backup_release_space
    printf '%s\n' "$(wc -l < "$(backup_reservation_file)")" > "$RESERVE_STATE/na-vrijgave"
)
read -r eerste tweede < "$RESERVE_STATE/uitkomst"
expect_equal "de eerste worker krijgt zijn ruimte gereserveerd" "0" "$eerste"
expect_equal "de tweede worker wordt geweigerd omdat de ruimte al vergeven is" "1" "$tweede"
expect_equal "na vrijgave staat er geen reservering meer in het grootboek" "0" \
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
    printf '999999999 /nergens\n' > "$(backup_reservation_file)"
    backup_reset_reservations
    printf '%s\n' "$(wc -l < "$(backup_reservation_file)")" > "$STALE_STATE/na-reset"
)
expect_equal "een blijven hangen reservering wordt bij een nieuwe run gewist" "0" \
    "$(cat "$STALE_STATE/na-reset")"

VERREKEN_STATE="$WORKROOT/verrekening"
mkdir -p "$VERREKEN_STATE" "$WORKROOT/bezig"
head -c 409600 /dev/zero > "$WORKROOT/bezig/files.tar.gz"
(
    WP2SHELL_STATE_DIR="$VERREKEN_STATE"
    backup_reset_reservations
    printf '1000 %s\n' "$WORKROOT/bezig" > "$(backup_reservation_file)"
    backup_ledger_outstanding_kilobytes "$(backup_reservation_file)" "" > "$VERREKEN_STATE/openstaand"
    printf '2000 %s\n' "$WORKROOT/bezig" > "$(backup_reservation_file)"
    backup_ledger_outstanding_kilobytes "$(backup_reservation_file)" "$WORKROOT/bezig" > "$VERREKEN_STATE/eigen-regel"
)
openstaand=$(cat "$VERREKEN_STATE/openstaand")
tests_run=$((tests_run + 1))
if [ "$openstaand" -gt 500 ] && [ "$openstaand" -lt 700 ]; then
    printf 'ok   al geschreven bytes worden van de reservering afgetrokken (%s van 1000 KB open)\n' "$openstaand"
else
    printf 'FAIL de verrekening klopt niet: %s KB open bij 1000 gereserveerd en 400 geschreven\n' "$openstaand" >&2
    tests_failed=$((tests_failed + 1))
fi
expect_equal "de eigen regel telt niet mee bij een hernieuwde reservering" "0" \
    "$(cat "$VERREKEN_STATE/eigen-regel")"

KAPOT_ROOT="$WORKROOT/kapot-manifest"
mkdir -p "$KAPOT_ROOT/20260801-120000-1" "$KAPOT_ROOT/20260813-120000-2/site1"
printf '{"tool":"wp2shell"}\n' > "$KAPOT_ROOT/20260801-120000-1/.wp2shell-run"
printf '{"tool":"wp2shell"}\n' > "$KAPOT_ROOT/20260813-120000-2/.wp2shell-run"
schrijf_herstelpunt "$KAPOT_ROOT/20260801-120000-1/site1"
head -c 1000 /dev/zero > "$KAPOT_ROOT/20260813-120000-2/site1/files.tar.gz"
: > "$KAPOT_ROOT/20260813-120000-2/site1/manifest.json"
touch -d '2026-08-01' "$KAPOT_ROOT/20260801-120000-1"
touch -d '2026-08-13' "$KAPOT_ROOT/20260813-120000-2"
KAPOT_CONF="$WORKROOT/kapot.conf"
sed "s|^WP2SHELL_BACKUP_DIR=.*|WP2SHELL_BACKUP_DIR=\"$KAPOT_ROOT\"|" "$REPO_ROOT/config/wp2shell.conf" > "$KAPOT_CONF"
WP2SHELL_CONFIG_FILE="$KAPOT_CONF" "$REPO_ROOT/tools/prune-backups.sh" --apply --keep 1 --lock-file "$WORKROOT/test.lock" >/dev/null 2>&1
expect_equal "een leeg manifest telt niet als herstelpunt en verdringt geen geldige backup" "aanwezig" \
    "$([ -f "$KAPOT_ROOT/20260801-120000-1/site1/manifest.json" ] && printf 'aanwezig' || printf 'weg')"

for optie in --keep --backup-dir --lock-file; do
    optie_status=0
    "$REPO_ROOT/tools/prune-backups.sh" --apply "$optie" >/dev/null 2>&1 || optie_status=$?
    expect_equal "de optie $optie zonder waarde wordt geweigerd" "2" "$optie_status"
done

printf 'dit is een bestand, geen map\n' > "$WORKROOT/blokkade"
gesloten_status=0
(
    WP2SHELL_STATE_DIR="$WORKROOT/blokkade/state"
    WP2SHELL_PARALLEL_JOBS=4
    backup_reserve_space 10 "$WORKROOT/worker-c" >/dev/null 2>&1
) || gesloten_status=1
expect_equal "een onbeschrijfbaar grootboek blokkeert de reservering bij parallel draaien" "1" "$gesloten_status"

sequentieel_status=0
(
    WP2SHELL_STATE_DIR="$WORKROOT/blokkade/state"
    WP2SHELL_PARALLEL_JOBS=1
    backup_reserve_space 10 "$WORKROOT/worker-c" >/dev/null 2>&1
) || sequentieel_status=1
expect_equal "sequentieel draaien loopt door zonder grootboek, want er is geen tweede worker" "0" "$sequentieel_status"

printf 'kostbare systeeminhoud\n' > "$WORKROOT/nep-systeembestand"
groot_bestand="$WORKROOT/groot-bestand"
head -c 8192 /dev/zero > "$groot_bestand"
slot_status=0
WP2SHELL_CONFIG_FILE="$CONF" "$REPO_ROOT/tools/prune-backups.sh" \
    --lock-file "$groot_bestand" >/dev/null 2>&1 || slot_status=$?
expect_equal "een gevuld bestand wordt geweigerd als lockbestand" "2" "$slot_status"
expect_equal "dat bestand is niet afgekapt" "8192" "$(stat -c '%s' -- "$groot_bestand")"

for waarde in abc -1 0 99999; do
    keep_status=0
    WP2SHELL_CONFIG_FILE="$CONF" "$REPO_ROOT/tools/prune-backups.sh" \
        --keep "$waarde" --lock-file "$WORKROOT/test.lock" >/dev/null 2>&1 || keep_status=$?
    expect_equal "de waarde $waarde voor --keep wordt geweigerd" "2" "$keep_status"
done

KAPOT2_ROOT="$WORKROOT/kapot-archief"
mkdir -p "$KAPOT2_ROOT/20260801-120000-1" "$KAPOT2_ROOT/20260813-120000-2/site1"
printf '{"tool":"wp2shell"}\n' > "$KAPOT2_ROOT/20260801-120000-1/.wp2shell-run"
printf '{"tool":"wp2shell"}\n' > "$KAPOT2_ROOT/20260813-120000-2/.wp2shell-run"
schrijf_herstelpunt "$KAPOT2_ROOT/20260801-120000-1/site1"
printf 'dit is geen geldig gzip-archief\n' > "$KAPOT2_ROOT/20260813-120000-2/site1/files.tar.gz"
printf 'CREATE TABLE wp_options;\n' > "$KAPOT2_ROOT/20260813-120000-2/site1/database.sql"
printf '{"run_id":"x","database_dump_bytes":24}\n' > "$KAPOT2_ROOT/20260813-120000-2/site1/manifest.json"
touch -d '2026-08-01' "$KAPOT2_ROOT/20260801-120000-1"
touch -d '2026-08-13' "$KAPOT2_ROOT/20260813-120000-2"
KAPOT2_CONF="$WORKROOT/kapot-archief.conf"
sed "s|^WP2SHELL_BACKUP_DIR=.*|WP2SHELL_BACKUP_DIR=\"$KAPOT2_ROOT\"|" "$REPO_ROOT/config/wp2shell.conf" > "$KAPOT2_CONF"
WP2SHELL_CONFIG_FILE="$KAPOT2_CONF" "$REPO_ROOT/tools/prune-backups.sh" \
    --apply --keep 1 --lock-file "$WORKROOT/test.lock" >/dev/null 2>&1
expect_equal "een onleesbaar archief telt niet als herstelpunt" "aanwezig" \
    "$([ -f "$KAPOT2_ROOT/20260801-120000-1/site1/manifest.json" ] && printf 'aanwezig' || printf 'weg')"

: > "$WP2SHELL_FINDINGS_FILE"
reservering_status=0
(
    WP2SHELL_STATE_DIR="$WORKROOT/blokkade/state"
    WP2SHELL_PARALLEL_JOBS=4
    WP2SHELL_BACKUP_FREE_MARGIN_PERCENT=1
    backup_space_is_sufficient "$SITE" "$WORKROOT" "$EIGENAAR" >/dev/null 2>&1
) || reservering_status=$?
expect_equal "een mislukte reservering slaat de site over" "1" "$reservering_status"
tests_run=$((tests_run + 1))
if grep -q '"category":"backup-reservation-unavailable"' "$WP2SHELL_FINDINGS_FILE"; then
    printf 'ok   dat wordt als reserveringsprobleem gemeld en niet als ruimtegebrek\n'
else
    printf 'FAIL een mislukte reservering wordt verkeerd gerapporteerd\n' >&2
    tests_failed=$((tests_failed + 1))
fi
tests_run=$((tests_run + 1))
if grep -q '"category":"backup-space-insufficient"' "$WP2SHELL_FINDINGS_FILE"; then
    printf 'FAIL er wordt ten onrechte ruimtegebrek gemeld\n' >&2
    tests_failed=$((tests_failed + 1))
else
    printf 'ok   er wordt geen ruimtegebrek gemeld terwijl er ruimte is\n'
fi

LOCKBEWIJS="$WORKROOT/klein-systeembestand"
printf 'kostbare configuratie\n' > "$LOCKBEWIJS"
lockbewijs_status=0
acquire_run_lock "$LOCKBEWIJS" >/dev/null 2>&1 || lockbewijs_status=1
expect_equal "een bestaand bestand zonder markering wordt geweigerd als slot" "1" "$lockbewijs_status"
expect_equal "de inhoud van dat bestand is onaangeroerd" "kostbare configuratie" "$(cat "$LOCKBEWIJS")"

VALSTRIK="$WORKROOT/valstrik-slot"
printf '123\ncritical-setting=yes\n' > "$VALSTRIK"
valstrik_status=0
acquire_run_lock "$VALSTRIK" >/dev/null 2>&1 || valstrik_status=1
expect_equal "een klein bestand dat begint met cijfers maar meer bevat wordt geweigerd" "1" "$valstrik_status"
expect_equal "de inhoud daarvan is onaangeroerd" "123
critical-setting=yes" "$(cat "$VALSTRIK")"

OUD_SLOT="$WORKROOT/oud-slot"
printf '12345\n' > "$OUD_SLOT"
oud_status=0
acquire_run_lock "$OUD_SLOT" >/dev/null 2>&1 || oud_status=1
expect_equal "een slot van de vorige versie wordt wel overgenomen" "0" "$oud_status"
release_run_lock

: > "$WP2SHELL_FINDINGS_FILE"
onmeetbaar_status=0
(
    WP2SHELL_STATE_DIR="$WORKROOT/state"
    backup_space_is_sufficient "$SITE" "$WORKROOT" "" >/dev/null 2>&1
) || onmeetbaar_status=$?
expect_equal "een onbekende databaseomvang blokkeert de backup niet" "0" "$onmeetbaar_status"

: > "$WP2SHELL_FINDINGS_FILE"
geschat_status=0
(
    WP2SHELL_STATE_DIR="$WORKROOT/state"
    PATH="$DFSHIM:$PATH"
    backup_space_is_sufficient "$SITE" "$WORKROOT" "" >/dev/null 2>&1
) || geschat_status=$?
expect_equal "bij te weinig ruimte wordt de schatting wel gemeld" "1" "$geschat_status"
tests_run=$((tests_run + 1))
if grep -q 'geschat, de werkelijke omvang was niet op te vragen' "$WP2SHELL_FINDINGS_FILE"; then
    printf 'ok   het bewijs vermeldt dat de databaseomvang geschat is\n'
else
    printf 'FAIL de schatting wordt niet als schatting gemeld\n' >&2
    tests_failed=$((tests_failed + 1))
fi

: > "$WP2SHELL_FINDINGS_FILE"
leeg_status=0
backup_space_is_sufficient "$WORKROOT/bestaat-echt-niet" "$WORKROOT" "$(id -un)" >/dev/null 2>&1 || leeg_status=$?
expect_equal "een onmeetbare docroot blokkeert de backup" "1" "$leeg_status"

: > "$WP2SHELL_FINDINGS_FILE"
uitgezet_status=0
(
    WP2SHELL_BACKUP_REQUIRE_SIZE_CHECK=0
    WP2SHELL_STATE_DIR="$WORKROOT/state"
    backup_space_is_sufficient "$SITE" "$WORKROOT" "" >/dev/null 2>&1
) || uitgezet_status=$?
expect_equal "met de controle bewust uitgezet loopt het door" "0" "$uitgezet_status"

: > "$WP2SHELL_FINDINGS_FILE"
uitgezet_krap=0
(
    WP2SHELL_BACKUP_REQUIRE_SIZE_CHECK=0
    WP2SHELL_STATE_DIR="$WORKROOT/state"
    PATH="$DFSHIM:$PATH"
    backup_space_is_sufficient "$SITE" "$WORKROOT" "$EIGENAAR" >/dev/null 2>&1
) || uitgezet_krap=$?
expect_equal "uitgezet betekent ook geen weigering bij een meetbare krappe site" "0" "$uitgezet_krap"

ATOOM_STATE="$WORKROOT/atomair"
mkdir -p "$ATOOM_STATE" "$WORKROOT/blijver" "$WORKROOT/vertrekker"
(
    WP2SHELL_STATE_DIR="$ATOOM_STATE"
    backup_reset_reservations
    printf '500 %s\n600 %s\n' "$WORKROOT/blijver" "$WORKROOT/vertrekker" > "$(backup_reservation_file)"
    WP2SHELL_BACKUP_RESERVED_DIRECTORY="$WORKROOT/vertrekker"
    backup_release_space
)
expect_equal "na vrijgave blijft de reservering van de andere worker staan" "1" \
    "$(grep -c 'blijver' "$ATOOM_STATE/backup-reservering")"
expect_equal "de vertrekkende reservering is verdwenen" "0" \
    "$(grep -c 'vertrekker' "$ATOOM_STATE/backup-reservering")"
expect_equal "er blijft geen tijdelijk grootboek achter" "0" \
    "$(find "$ATOOM_STATE" -name 'backup-reservering.*' -not -name '*.lock' | wc -l | tr -d ' ')"

GZIP_ROOT="$WORKROOT/gzip-stuk"
mkdir -p "$GZIP_ROOT/20260813-120000-1"
printf '{"tool":"wp2shell"}\n' > "$GZIP_ROOT/20260813-120000-1/.wp2shell-run"
schrijf_herstelpunt "$GZIP_ROOT/20260813-120000-1/site1"
GZIP_CONF="$WORKROOT/gzip.conf"
sed "s|^WP2SHELL_BACKUP_DIR=.*|WP2SHELL_BACKUP_DIR=\"$GZIP_ROOT\"|" "$REPO_ROOT/config/wp2shell.conf" > "$GZIP_CONF"
GZIP_SHIM="$WORKROOT/gzip-shim"
mkdir -p "$GZIP_SHIM"
printf '#!/bin/bash\nexit 127\n' > "$GZIP_SHIM/gzip"
chmod 0755 -- "$GZIP_SHIM/gzip"
gzip_status=0
PATH="$GZIP_SHIM:$PATH" WP2SHELL_CONFIG_FILE="$GZIP_CONF" \
    "$REPO_ROOT/tools/prune-backups.sh" --apply --lock-file "$WORKROOT/test.lock" >/dev/null 2>&1 || gzip_status=$?
expect_equal "een gzip die niet werkt stopt het opruimen" "2" "$gzip_status"
expect_equal "het herstelpunt is niet verwijderd" "aanwezig" \
    "$([ -f "$GZIP_ROOT/20260813-120000-1/site1/manifest.json" ] && printf 'aanwezig' || printf 'weg')"

: > "$WP2SHELL_FINDINGS_FILE"
KRAP_STATE="$WORKROOT/krapte"
mkdir -p "$KRAP_STATE" "$WORKROOT/andere-worker"
krapte_status=0
(
    WP2SHELL_STATE_DIR="$KRAP_STATE"
    backup_reset_reservations
    beschikbaar=$(backup_available_kilobytes "$WORKROOT")
    printf '%s %s\n' "$((beschikbaar - 10))" "$WORKROOT/andere-worker" > "$(backup_reservation_file)"
    backup_space_is_sufficient "$SITE" "$WORKROOT" "$EIGENAAR" >/dev/null 2>&1
) || krapte_status=$?
expect_equal "krapte door gelijktijdige backups slaat de site over" "1" "$krapte_status"
tests_run=$((tests_run + 1))
if grep -q '"category":"backup-space-insufficient"' "$WP2SHELL_FINDINGS_FILE"; then
    printf 'ok   krapte wordt als ruimtegebrek gemeld en niet als grootboekprobleem\n'
else
    printf 'FAIL krapte wordt verkeerd gerapporteerd\n' >&2
    tests_failed=$((tests_failed + 1))
fi
tests_run=$((tests_run + 1))
if grep -q '"category":"backup-reservation-unavailable"' "$WP2SHELL_FINDINGS_FILE"; then
    printf 'FAIL krapte wordt ten onrechte als grootboekprobleem gemeld\n' >&2
    tests_failed=$((tests_failed + 1))
else
    printf 'ok   er wordt niet ten onrechte naar de state-map verwezen\n'
fi

marge_status=0
(
    WP2SHELL_STATE_DIR="$WORKROOT/state"
    WP2SHELL_BACKUP_FREE_MARGIN_PERCENT=999999999999999999
    backup_space_is_sufficient "$SITE" "$WORKROOT" "$EIGENAAR" >/dev/null 2>&1
) || marge_status=$?
expect_equal "een absurde marge laat de backup niet zomaar door" "0" "$marge_status"

PERSITE_ROOT="$WORKROOT/per-site"
mkdir -p "$PERSITE_ROOT/20260801-120000-1" "$PERSITE_ROOT/20260810-120000-2" "$PERSITE_ROOT/20260813-120000-3"
for run in 20260801-120000-1 20260810-120000-2 20260813-120000-3; do
    printf '{"tool":"wp2shell"}\n' > "$PERSITE_ROOT/$run/.wp2shell-run"
done
schrijf_herstelpunt "$PERSITE_ROOT/20260801-120000-1/site-b"
schrijf_herstelpunt "$PERSITE_ROOT/20260810-120000-2/site-a"
schrijf_herstelpunt "$PERSITE_ROOT/20260813-120000-3/site-a"
PERSITE_CONF="$WORKROOT/per-site.conf"
sed "s|^WP2SHELL_BACKUP_DIR=.*|WP2SHELL_BACKUP_DIR=\"$PERSITE_ROOT\"|" "$REPO_ROOT/config/wp2shell.conf" > "$PERSITE_CONF"
WP2SHELL_CONFIG_FILE="$PERSITE_CONF" "$REPO_ROOT/tools/prune-backups.sh" \
    --apply --keep 1 --lock-file "$WORKROOT/test.lock" >/dev/null 2>&1
expect_equal "de enige backup van site b overleeft twee nieuwere runs zonder site b" "aanwezig" \
    "$([ -f "$PERSITE_ROOT/20260801-120000-1/site-b/manifest.json" ] && printf 'aanwezig' || printf 'weg')"
expect_equal "van site a blijft alleen de nieuwste staan" "aanwezig" \
    "$([ -f "$PERSITE_ROOT/20260813-120000-3/site-a/manifest.json" ] && printf 'aanwezig' || printf 'weg')"
expect_equal "de oudere backup van site a is opgeruimd" "weg" \
    "$([ -d "$PERSITE_ROOT/20260810-120000-2/site-a" ] && printf 'aanwezig' || printf 'weg')"

TIJDSTIP_ROOT="$WORKROOT/tijdstip"
mkdir -p "$TIJDSTIP_ROOT/20260801-120000-1" "$TIJDSTIP_ROOT/20260813-120000-2"
printf '{"tool":"wp2shell"}\n' > "$TIJDSTIP_ROOT/20260801-120000-1/.wp2shell-run"
printf '{"tool":"wp2shell"}\n' > "$TIJDSTIP_ROOT/20260813-120000-2/.wp2shell-run"
schrijf_herstelpunt "$TIJDSTIP_ROOT/20260801-120000-1/site1"
schrijf_herstelpunt "$TIJDSTIP_ROOT/20260813-120000-2/site1"
touch -d '2026-08-20' "$TIJDSTIP_ROOT/20260801-120000-1"
touch -d '2026-08-02' "$TIJDSTIP_ROOT/20260813-120000-2"
TIJDSTIP_CONF="$WORKROOT/tijdstip.conf"
sed "s|^WP2SHELL_BACKUP_DIR=.*|WP2SHELL_BACKUP_DIR=\"$TIJDSTIP_ROOT\"|" "$REPO_ROOT/config/wp2shell.conf" > "$TIJDSTIP_CONF"
WP2SHELL_CONFIG_FILE="$TIJDSTIP_CONF" "$REPO_ROOT/tools/prune-backups.sh" \
    --apply --keep 1 --lock-file "$WORKROOT/test.lock" >/dev/null 2>&1
expect_equal "een aangeraakte mtime verandert de volgorde niet, de run-id telt" "aanwezig" \
    "$([ -f "$TIJDSTIP_ROOT/20260813-120000-2/site1/manifest.json" ] && printf 'aanwezig' || printf 'weg')"

EIGENNAAM_ROOT="$WORKROOT/eigen-run-id"
mkdir -p "$EIGENNAAM_ROOT/handmatig" "$EIGENNAAM_ROOT/20260813-120000-2"
printf '{"tool":"wp2shell","created_at":"2026-08-01T10:00:00Z"}\n' > "$EIGENNAAM_ROOT/handmatig/.wp2shell-run"
printf '{"tool":"wp2shell","created_at":"2026-08-13T10:00:00Z"}\n' > "$EIGENNAAM_ROOT/20260813-120000-2/.wp2shell-run"
schrijf_herstelpunt "$EIGENNAAM_ROOT/handmatig/site1"
schrijf_herstelpunt "$EIGENNAAM_ROOT/20260813-120000-2/site1"
EIGENNAAM_CONF="$WORKROOT/eigen-run-id.conf"
sed "s|^WP2SHELL_BACKUP_DIR=.*|WP2SHELL_BACKUP_DIR=\"$EIGENNAAM_ROOT\"|" "$REPO_ROOT/config/wp2shell.conf" > "$EIGENNAAM_CONF"
eigennaam_status=0
WP2SHELL_CONFIG_FILE="$EIGENNAAM_CONF" "$REPO_ROOT/tools/prune-backups.sh" \
    --apply --keep 1 --lock-file "$WORKROOT/test.lock" >/dev/null 2>&1 || eigennaam_status=$?
expect_equal "een run met een eigen run-id blokkeert het opruimen niet" "0" "$eigennaam_status"
expect_equal "de markering bepaalt de volgorde, niet de mapnaam" "aanwezig" \
    "$([ -f "$EIGENNAAM_ROOT/20260813-120000-2/site1/manifest.json" ] && printf 'aanwezig' || printf 'weg')"
expect_equal "de oudere run met eigen naam is opgeruimd" "weg" \
    "$([ -d "$EIGENNAAM_ROOT/handmatig/site1" ] && printf 'aanwezig' || printf 'weg')"

DUBBEL_ROOT="$WORKROOT/dubbeltelling"
mkdir -p "$DUBBEL_ROOT/20260801-120000-1/site-onvolledig" "$DUBBEL_ROOT/20260813-120000-2"
printf '{"tool":"wp2shell"}\n' > "$DUBBEL_ROOT/20260801-120000-1/.wp2shell-run"
printf '{"tool":"wp2shell"}\n' > "$DUBBEL_ROOT/20260813-120000-2/.wp2shell-run"
schrijf_herstelpunt "$DUBBEL_ROOT/20260801-120000-1/site1"
schrijf_herstelpunt "$DUBBEL_ROOT/20260813-120000-2/site1"
head -c 2000000 /dev/zero > "$DUBBEL_ROOT/20260801-120000-1/site-onvolledig/files.tar.gz"
DUBBEL_CONF="$WORKROOT/dubbel.conf"
sed "s|^WP2SHELL_BACKUP_DIR=.*|WP2SHELL_BACKUP_DIR=\"$DUBBEL_ROOT\"|" "$REPO_ROOT/config/wp2shell.conf" > "$DUBBEL_CONF"
droog=$(WP2SHELL_CONFIG_FILE="$DUBBEL_CONF" "$REPO_ROOT/tools/prune-backups.sh" \
    --keep 1 --lock-file "$WORKROOT/test.lock" 2>/dev/null | sed -n 's/.*zouden verwijderd worden, samen \([0-9]*\) MB/\1/p')
echt=$(WP2SHELL_CONFIG_FILE="$DUBBEL_CONF" "$REPO_ROOT/tools/prune-backups.sh" \
    --apply --keep 1 --lock-file "$WORKROOT/test.lock" 2>/dev/null | sed -n 's/.*mappen verwijderd, \([0-9]*\) MB teruggewonnen/\1/p')
expect_equal "de droge run schat evenveel als er werkelijk vrijkomt" "$echt" "$droog"

NEPTAR_ROOT="$WORKROOT/neparchief"
mkdir -p "$NEPTAR_ROOT/20260801-120000-1" "$NEPTAR_ROOT/20260813-120000-2/site1"
printf '{"tool":"wp2shell"}\n' > "$NEPTAR_ROOT/20260801-120000-1/.wp2shell-run"
printf '{"tool":"wp2shell"}\n' > "$NEPTAR_ROOT/20260813-120000-2/.wp2shell-run"
schrijf_herstelpunt "$NEPTAR_ROOT/20260801-120000-1/site1"
head -c 5000 /dev/urandom | gzip -c > "$NEPTAR_ROOT/20260813-120000-2/site1/files.tar.gz"
printf 'CREATE TABLE wp_options (id int);\n' > "$NEPTAR_ROOT/20260813-120000-2/site1/database.sql"
printf '{"files_archive_bytes":%s,"database_dump_bytes":%s}\n' \
    "$(stat -c '%s' -- "$NEPTAR_ROOT/20260813-120000-2/site1/files.tar.gz")" \
    "$(stat -c '%s' -- "$NEPTAR_ROOT/20260813-120000-2/site1/database.sql")" \
    > "$NEPTAR_ROOT/20260813-120000-2/site1/manifest.json"
NEPTAR_CONF="$WORKROOT/neparchief.conf"
sed "s|^WP2SHELL_BACKUP_DIR=.*|WP2SHELL_BACKUP_DIR=\"$NEPTAR_ROOT\"|" "$REPO_ROOT/config/wp2shell.conf" > "$NEPTAR_CONF"
WP2SHELL_CONFIG_FILE="$NEPTAR_CONF" "$REPO_ROOT/tools/prune-backups.sh" \
    --apply --keep 1 --lock-file "$WORKROOT/test.lock" >/dev/null 2>&1
expect_equal "een gzip zonder tar erin telt niet als herstelpunt" "weg" \
    "$([ -d "$NEPTAR_ROOT/20260813-120000-2/site1" ] && printf 'aanwezig' || printf 'weg')"
expect_equal "de geldige oudere backup blijft daardoor staan" "aanwezig" \
    "$([ -f "$NEPTAR_ROOT/20260801-120000-1/site1/manifest.json" ] && printf 'aanwezig' || printf 'weg')"

GEMENGD_ROOT="$WORKROOT/gemengd"
mkdir -p "$GEMENGD_ROOT/20260813-120000-1" "$GEMENGD_ROOT/20260814-090000-2"
schrijf_herstelpunt "$GEMENGD_ROOT/20260813-120000-1/site1"
schrijf_herstelpunt "$GEMENGD_ROOT/20260814-090000-2/site1"
printf '{"tool":"wp2shell","created_at":"2026-08-14T09:00:00Z"}\n' > "$GEMENGD_ROOT/20260814-090000-2/.wp2shell-run"
GEMENGD_CONF="$WORKROOT/gemengd.conf"
sed "s|^WP2SHELL_BACKUP_DIR=.*|WP2SHELL_BACKUP_DIR=\"$GEMENGD_ROOT\"|" "$REPO_ROOT/config/wp2shell.conf" > "$GEMENGD_CONF"
WP2SHELL_CONFIG_FILE="$GEMENGD_CONF" "$REPO_ROOT/tools/prune-backups.sh" \
    --apply --keep 1 --lock-file "$WORKROOT/test.lock" >/dev/null 2>&1
expect_equal "in een gemengde boom overleeft het nieuwste herstelpunt" "aanwezig" \
    "$([ -f "$GEMENGD_ROOT/20260814-090000-2/site1/manifest.json" ] && printf 'aanwezig' || printf 'weg')"
expect_equal "en het oudere zonder markering wordt opgeruimd" "weg" \
    "$([ -d "$GEMENGD_ROOT/20260813-120000-1/site1" ] && printf 'aanwezig' || printf 'weg')"

GELIJK_ROOT="$WORKROOT/zelfde-seconde"
mkdir -p "$GELIJK_ROOT/20260814-090000-100" "$GELIJK_ROOT/20260814-090000-101"
for run in 20260814-090000-100 20260814-090000-101; do
    printf '{"tool":"wp2shell","created_at":"2026-08-14T09:00:00Z"}\n' > "$GELIJK_ROOT/$run/.wp2shell-run"
    schrijf_herstelpunt "$GELIJK_ROOT/$run/site1"
done
GELIJK_CONF="$WORKROOT/zelfde-seconde.conf"
sed "s|^WP2SHELL_BACKUP_DIR=.*|WP2SHELL_BACKUP_DIR=\"$GELIJK_ROOT\"|" "$REPO_ROOT/config/wp2shell.conf" > "$GELIJK_CONF"
WP2SHELL_CONFIG_FILE="$GELIJK_CONF" "$REPO_ROOT/tools/prune-backups.sh" \
    --apply --keep 1 --lock-file "$WORKROOT/test.lock" >/dev/null 2>&1
expect_equal "bij een gelijk tijdstip wint de laatst gestarte run" "aanwezig" \
    "$([ -f "$GELIJK_ROOT/20260814-090000-101/site1/manifest.json" ] && printf 'aanwezig' || printf 'weg')"
expect_equal "en de eerder gestarte wordt opgeruimd" "weg" \
    "$([ -d "$GELIJK_ROOT/20260814-090000-100/site1" ] && printf 'aanwezig' || printf 'weg')"

ROMMEL_ROOT="$WORKROOT/rommel"
mkdir -p "$ROMMEL_ROOT/eigennaam" "$ROMMEL_ROOT/20260814-090000-2"
printf '{"tool":"wp2shell","created_at":"2026-08-01T09:00:00Z"}\n' > "$ROMMEL_ROOT/eigennaam/.wp2shell-run"
printf 'rommel\n' > "$ROMMEL_ROOT/eigennaam/los-bestand"
printf '{"tool":"wp2shell","created_at":"2026-08-14T09:00:00Z"}\n' > "$ROMMEL_ROOT/20260814-090000-2/.wp2shell-run"
schrijf_herstelpunt "$ROMMEL_ROOT/20260814-090000-2/site1"
ROMMEL_CONF="$WORKROOT/rommel.conf"
sed "s|^WP2SHELL_BACKUP_DIR=.*|WP2SHELL_BACKUP_DIR=\"$ROMMEL_ROOT\"|" "$REPO_ROOT/config/wp2shell.conf" > "$ROMMEL_CONF"
WP2SHELL_CONFIG_FILE="$ROMMEL_CONF" "$REPO_ROOT/tools/prune-backups.sh" \
    --apply --lock-file "$WORKROOT/test.lock" >/dev/null 2>&1
expect_equal "een runmap met los bestand houdt zijn markering" "aanwezig" \
    "$([ -f "$ROMMEL_ROOT/eigennaam/.wp2shell-run" ] && printf 'aanwezig' || printf 'weg')"
rommel_status=0
WP2SHELL_CONFIG_FILE="$ROMMEL_CONF" "$REPO_ROOT/tools/prune-backups.sh" \
    --lock-file "$WORKROOT/test.lock" >/dev/null 2>&1 || rommel_status=$?
expect_equal "de boom blijft daardoor bruikbaar bij een volgende run" "0" "$rommel_status"

LEEG_ROOT="$WORKROOT/lege-eigennaam"
mkdir -p "$LEEG_ROOT/handmatig" "$LEEG_ROOT/20260814-090000-2"
printf '{"tool":"wp2shell","created_at":"2026-08-01T09:00:00Z"}\n' > "$LEEG_ROOT/handmatig/.wp2shell-run"
printf '{"tool":"wp2shell","created_at":"2026-08-14T09:00:00Z"}\n' > "$LEEG_ROOT/20260814-090000-2/.wp2shell-run"
schrijf_herstelpunt "$LEEG_ROOT/20260814-090000-2/site1"
LEEG_CONF="$WORKROOT/lege-eigennaam.conf"
sed "s|^WP2SHELL_BACKUP_DIR=.*|WP2SHELL_BACKUP_DIR=\"$LEEG_ROOT\"|" "$REPO_ROOT/config/wp2shell.conf" > "$LEEG_CONF"
WP2SHELL_CONFIG_FILE="$LEEG_CONF" "$REPO_ROOT/tools/prune-backups.sh" \
    --apply --lock-file "$WORKROOT/test.lock" >/dev/null 2>&1
expect_equal "een runmap met alleen een markering wordt wel opgeruimd" "weg" \
    "$([ -d "$LEEG_ROOT/handmatig" ] && printf 'aanwezig' || printf 'weg')"

CHRONO_ROOT="$WORKROOT/chronologie"
mkdir -p "$CHRONO_ROOT/z-oud" "$CHRONO_ROOT/a-nieuw"
printf '{"tool":"wp2shell","created_at":"2026-08-14T09:00:00Z"}\n' > "$CHRONO_ROOT/z-oud/.wp2shell-run"
schrijf_herstelpunt "$CHRONO_ROOT/z-oud/site1"
sleep 0.2
printf '{"tool":"wp2shell","created_at":"2026-08-14T09:00:00Z"}\n' > "$CHRONO_ROOT/a-nieuw/.wp2shell-run"
schrijf_herstelpunt "$CHRONO_ROOT/a-nieuw/site1"
CHRONO_CONF="$WORKROOT/chronologie.conf"
sed "s|^WP2SHELL_BACKUP_DIR=.*|WP2SHELL_BACKUP_DIR=\"$CHRONO_ROOT\"|" "$REPO_ROOT/config/wp2shell.conf" > "$CHRONO_CONF"
WP2SHELL_CONFIG_FILE="$CHRONO_CONF" "$REPO_ROOT/tools/prune-backups.sh" \
    --apply --keep 1 --lock-file "$WORKROOT/test.lock" >/dev/null 2>&1
expect_equal "bij eigen namen in dezelfde seconde telt het echte aanmaakmoment" "aanwezig" \
    "$([ -f "$CHRONO_ROOT/a-nieuw/site1/manifest.json" ] && printf 'aanwezig' || printf 'weg')"
expect_equal "de eerder aangemaakte run wordt opgeruimd ondanks zijn latere naam" "weg" \
    "$([ -d "$CHRONO_ROOT/z-oud/site1" ] && printf 'aanwezig' || printf 'weg')"

STAART="$WORKROOT/slot-met-staart"
printf '123\n\n' > "$STAART"
staart_status=0
acquire_run_lock "$STAART" >/dev/null 2>&1 || staart_status=1
expect_equal "een slot met een extra lege regel wordt geweigerd" "1" "$staart_status"
expect_equal "de grootte daarvan is onveranderd" "5" "$(stat -c '%s' -- "$STAART")"

OUDRUN_ROOT="$WORKROOT/oude-run-zonder-markering"
mkdir -p "$OUDRUN_ROOT/20260801-120000-1" "$OUDRUN_ROOT/20260814-090000-2"
schrijf_herstelpunt "$OUDRUN_ROOT/20260801-120000-1/site1"
schrijf_herstelpunt "$OUDRUN_ROOT/20260814-090000-2/site1"
printf '{"tool":"wp2shell","created_at":"2026-08-14T09:00:00Z"}\n' > "$OUDRUN_ROOT/20260814-090000-2/.wp2shell-run"
OUDRUN_CONF="$WORKROOT/oude-run.conf"
sed "s|^WP2SHELL_BACKUP_DIR=.*|WP2SHELL_BACKUP_DIR=\"$OUDRUN_ROOT\"|" "$REPO_ROOT/config/wp2shell.conf" > "$OUDRUN_CONF"
WP2SHELL_CONFIG_FILE="$OUDRUN_CONF" "$REPO_ROOT/tools/prune-backups.sh" \
    --apply --keep 1 --lock-file "$WORKROOT/test.lock" >/dev/null 2>&1
expect_equal "een run zonder markering laat na het opruimen geen lege map achter" "weg" \
    "$([ -d "$OUDRUN_ROOT/20260801-120000-1" ] && printf 'aanwezig' || printf 'weg')"
expect_equal "het nieuwste herstelpunt blijft daarbij staan" "aanwezig" \
    "$([ -f "$OUDRUN_ROOT/20260814-090000-2/site1/manifest.json" ] && printf 'aanwezig' || printf 'weg')"

printf '%s tests, %s mislukt\n' "$tests_run" "$tests_failed"
if [ "$tests_failed" -gt 0 ]; then
    exit 1
fi
exit 0
