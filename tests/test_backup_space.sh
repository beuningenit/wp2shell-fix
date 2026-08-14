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

CONF="$WORKROOT/prune.conf"
sed "s|^WP2SHELL_BACKUP_DIR=.*|WP2SHELL_BACKUP_DIR=\"$PRUNE_ROOT\"|" "$REPO_ROOT/config/wp2shell.conf" > "$CONF"

WP2SHELL_CONFIG_FILE="$CONF" "$REPO_ROOT/tools/prune-backups.sh" >/dev/null 2>&1
expect_equal "zonder --apply wordt er niets verwijderd" "4" \
    "$(find "$PRUNE_ROOT" -mindepth 2 -maxdepth 2 -type d | wc -l | tr -d ' ')"

WP2SHELL_CONFIG_FILE="$CONF" "$REPO_ROOT/tools/prune-backups.sh" --apply >/dev/null 2>&1
expect_equal "met --apply blijven alleen de herstelpunten over" "1" \
    "$(find "$PRUNE_ROOT" -mindepth 2 -maxdepth 2 -type d | wc -l | tr -d ' ')"
expect_equal "het herstelpunt zelf is bewaard" "1" \
    "$(find "$PRUNE_ROOT" -name manifest.json -type f | wc -l | tr -d ' ')"

ORDER_ROOT="$WORKROOT/volgorde"
mkdir -p "$ORDER_ROOT/20260801-120000-1/site1" "$ORDER_ROOT/20260801-120000-1/site-onvolledig" "$ORDER_ROOT/20260813-120000-2/site1"
printf '{}\n' > "$ORDER_ROOT/20260801-120000-1/site1/manifest.json"
printf '{}\n' > "$ORDER_ROOT/20260813-120000-2/site1/manifest.json"
head -c 1000 /dev/zero > "$ORDER_ROOT/20260801-120000-1/site-onvolledig/files.tar.gz"
touch -d '2026-08-01' "$ORDER_ROOT/20260801-120000-1"
touch -d '2026-08-13' "$ORDER_ROOT/20260813-120000-2"
ORDER_CONF="$WORKROOT/volgorde.conf"
sed "s|^WP2SHELL_BACKUP_DIR=.*|WP2SHELL_BACKUP_DIR=\"$ORDER_ROOT\"|" "$REPO_ROOT/config/wp2shell.conf" > "$ORDER_CONF"
WP2SHELL_CONFIG_FILE="$ORDER_CONF" "$REPO_ROOT/tools/prune-backups.sh" --apply --keep 1 >/dev/null 2>&1
expect_equal "de nieuwste run met een herstelpunt overleeft het opruimen" "aanwezig" \
    "$([ -d "$ORDER_ROOT/20260813-120000-2" ] && printf 'aanwezig' || printf 'weg')"
expect_equal "de oudere run wordt wel opgeruimd" "weg" \
    "$([ -d "$ORDER_ROOT/20260801-120000-1" ] && printf 'aanwezig' || printf 'weg')"

DRY_ROOT="$WORKROOT/droog"
mkdir -p "$DRY_ROOT/20260813-120000-9" "$DRY_ROOT/20260813-120000-1/site1"
printf '{}\n' > "$DRY_ROOT/20260813-120000-1/site1/manifest.json"
DRY_CONF="$WORKROOT/droog.conf"
sed "s|^WP2SHELL_BACKUP_DIR=.*|WP2SHELL_BACKUP_DIR=\"$DRY_ROOT\"|" "$REPO_ROOT/config/wp2shell.conf" > "$DRY_CONF"
voor=$(find "$DRY_ROOT" | LC_ALL=C sort)
WP2SHELL_CONFIG_FILE="$DRY_CONF" "$REPO_ROOT/tools/prune-backups.sh" >/dev/null 2>&1
na=$(find "$DRY_ROOT" | LC_ALL=C sort)
expect_equal "zonder --apply verandert er niets op de schijf, ook geen lege runmap" "$voor" "$na"

FAIL_ROOT="$WORKROOT/onverwijderbaar"
mkdir -p "$FAIL_ROOT/20260813-120000-1/site-onvolledig"
head -c 100 /dev/zero > "$FAIL_ROOT/20260813-120000-1/site-onvolledig/files.tar.gz"
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
    "$REPO_ROOT/tools/prune-backups.sh" --apply >/dev/null 2>&1 || fail_status=$?
expect_equal "een mislukte verwijdering geeft een exitcode die niet nul is" "1" "$fail_status"
expect_equal "de map die niet verwijderd kon worden staat er nog" "aanwezig" \
    "$([ -d "$FAIL_ROOT/20260813-120000-1/site-onvolledig" ] && printf 'aanwezig' || printf 'weg')"

UNSAFE_CONF="$WORKROOT/onveilig.conf"
sed "s|^WP2SHELL_BACKUP_DIR=.*|WP2SHELL_BACKUP_DIR=\"/\"|" "$REPO_ROOT/config/wp2shell.conf" > "$UNSAFE_CONF"
unsafe_status=0
WP2SHELL_CONFIG_FILE="$UNSAFE_CONF" "$REPO_ROOT/tools/prune-backups.sh" --apply >/dev/null 2>&1 || unsafe_status=$?
expect_equal "de hoofdmap wordt geweigerd als backupboom" "2" "$unsafe_status"

VREEMD_ROOT="$WORKROOT/vreemde-boom"
mkdir -p "$VREEMD_ROOT/klantdata"
VREEMD_CONF="$WORKROOT/vreemd.conf"
sed "s|^WP2SHELL_BACKUP_DIR=.*|WP2SHELL_BACKUP_DIR=\"$VREEMD_ROOT\"|" "$REPO_ROOT/config/wp2shell.conf" > "$VREEMD_CONF"
vreemd_status=0
WP2SHELL_CONFIG_FILE="$VREEMD_CONF" "$REPO_ROOT/tools/prune-backups.sh" --apply >/dev/null 2>&1 || vreemd_status=$?
expect_equal "een map zonder runmappen wordt geweigerd" "2" "$vreemd_status"
expect_equal "de vreemde inhoud is onaangeroerd" "aanwezig" \
    "$([ -d "$VREEMD_ROOT/klantdata" ] && printf 'aanwezig' || printf 'weg')"

printf '%s tests, %s mislukt\n' "$tests_run" "$tests_failed"
if [ "$tests_failed" -gt 0 ]; then
    exit 1
fi
exit 0
