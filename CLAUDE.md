# CLAUDE.md

Werkafspraken en conventies voor de wp2shell-remediation toolkit.

Deze toolkit draait op productie-omgevingen van klanten (DirectAdmin + OpenLiteSpeed shared hosting).
Alles in dit document is bindend, niet adviserend.

## Doel

Alle WordPress-installaties op een server inventariseren, controleren op de wp2shell-infectie
(CVE-2026-63030 REST batch route-confusion RCE, geketend met CVE-2026-60137 author_exclude SQL-injectie),
besmette sites opschonen, en herbesmetting via dit lek onmogelijk maken.

Dit is een defensieve toolkit. Er wordt geen exploitcode geschreven, opgenomen of gereproduceerd.

## Harde codeconventies

### Geen commentaarregels

De opgeleverde scripts bevatten geen commentaarregels. Uitzonderingen, en alleen deze:

- De shebang (`#!/bin/bash`). Dat is geen commentaar maar een kernel-directive, waar hij ook staat.
  Testbestanden genereren soms een hulpscript met een eigen shebang in een heredoc; die telt ook mee.
- `# BEGIN wp2shell` / `# END wp2shell` markers in gegenereerde `.htaccess`-payloads. Die zijn functioneel:
  ze maken idempotente vervanging van het blok mogelijk, net als WordPress' eigen
  `# BEGIN WordPress` blok.
- Verplichte headers in gegenereerde WordPress mu-plugins (`Plugin Name:`), die WordPress zelf parseert.

Gevolg: de code moet zonder `# shellcheck disable=` directives shellcheck-schoon zijn. Los de
onderliggende constructie op in plaats van de waarschuwing te onderdrukken. Uitsluitingen staan op de
commandoregel in `tools/lint.sh`, met deze motivering:

- `SC1090` en `SC1091`: het configuratiebestand wordt op runtime gesourced en het pad is variabel.
- `SC2034`: `lib/common.sh` is een gedeelde library. Variabelen die daar gedefinieerd worden lijken
  ongebruikt maar worden door de andere modules geconsumeerd.
- `SC2016`: strings met `$argv[1]` of `$wp_version` zijn PHP-broncode of een grep-patroon. Die mogen
  juist niet door Bash geexpandeerd worden.
- `SC2029`: `deploy.sh` expandeert bewust aan de clientkant, want het doelpad is een lokale
  variabele die voor verzending ingevuld moet worden. De invoer wordt eerst gevalideerd op
  shell-metatekens.
- `SC2030` en `SC2031`: bij parallelle verwerking krijgt elke worker bewust een eigen
  findings-bestand in zijn subshell, terwijl de ouder het zijne houdt om na afloop samen te voegen.
- `SC2329`: handlerfuncties worden indirect aangeroepen via een variabele, zodat elk subcommando
  dezelfde per-site isolatie gebruikt.
- `SC2254`: allowlist-entries zijn bewust globs, geen letterlijke strings. `*@beuningenit.nl` en
  `/home/*/domains/*/public_html/maatwerk/*` moeten als patroon matchen.

`tools/lint.sh` draait shellcheck, controleert op em dash en en dash, en faalt op elke
commentaarregel behalve de shebang.

Gevolg: identifiers en structuur moeten zichzelf verklaren. Kies lange, beschrijvende functienamen.

### Geen em dash

Nergens een em dash (codepunt U+2014). Niet in code, niet in strings, niet in output, niet in
documentatie, niet in gegenereerde rapporten of e-mails, niet in commitberichten. Gebruik een gewone
koppelstreep, een dubbele punt, of herformuleer. Dit geldt ook voor de en dash (codepunt U+2013).

De literale tekens staan bewust nergens in deze repository, ook niet in dit document. `tools/lint.sh`
faalt zodra ze ergens opduiken.

### Taal

- Mensgerichte output in het Nederlands: rapportsamenvattingen, e-mails, README, foutmeldingen die
  een beheerder leest.
- Code-identifiers, functienamen, variabelen, JSON-sleutels, logsleutels en technische termen in het
  Engels.
- Geen diakritische ellende: rapporten zijn UTF-8 en mail wordt als UTF-8 verstuurd.

## Stack

- Bash als orkestrator. Bash 4+ constructies zijn toegestaan.
- WP-CLI als motor voor alle WordPress-operaties.
- PHP alleen waar Bash tekortschiet.
- Afhankelijkheden minimaal houden. Bij de start controleren: `php`, mariadb/mysql-client, `find`,
  `grep`, `sha1sum`, `curl`, `tar`, `flock`. Ontbreekt WP-CLI, haal dan `wp-cli.phar` op naar een
  lokaal pad en gebruik die.
- Optioneel en runtime gedetecteerd, nooit een harde eis: `jq`, `clamscan` / `clamdscan`, `nice`,
  `ionice`, ModSecurity, Softaculous.

## Veiligheidsprincipes

Deze zijn niet-onderhandelbaar. Elke PR wordt hierop getoetst.

1. **Report-first.** Standaardmodus is uitsluitend inventariseren en rapporteren, zonder enige
   wijziging. Wijzigende acties gebeuren alleen met `--apply`, plus aparte opt-in vlaggen per
   gevoelige categorie (`--remove-admins`).
2. **Backup vooraf, verplicht.** Voor elke wijziging aan een site eerst een volledige backup van
   bestanden en database, buiten de docroot en niet publiek benaderbaar. Backup mislukt betekent:
   die site overslaan. Niet doorgaan.
3. **Quarantaine in plaats van verwijderen.** Verdachte of bevestigd kwaadaardige bestanden gaan naar
   een quarantainelocatie met manifest (oorspronkelijk pad, hash, reden, tijdstip, gebruiker).
   Niets wordt hard verwijderd. Alles blijft herstelbaar en bewijs blijft behouden.
4. **Draai als de juiste gebruiker.** Bestands- en WP-CLI-operaties draaien als de systeemgebruiker
   die eigenaar is van de installatie, via `sudo -u <user>`. Nooit als root in gebruikersmappen.
   `wp --allow-root` is verboden: root-eigendom breekt de site.
5. **Idempotent en herhaalbaar.** Meermaals draaien levert geen schade en geen dubbele acties op.
6. **Per-site isolatie.** Een fout op een site stopt de verwerking van andere sites niet. Elke site
   krijgt een eigen resultaat in het rapport, inclusief een eigen foutstatus.
7. **Beheerst met serverbelasting.** Gedeelde server met andere klanten. Sequentieel als standaard,
   optioneel begrensde parallelisatie, `nice`/`ionice` waar beschikbaar. Eenmalige uitvoering
   afdwingen met een lockfile.
8. **Volledige audittrail.** Elke verplaatste of gewijzigde file wordt gelogd met hashes en reden.
9. **Allowlist tegen false positives.** Configureerbare allowlist voor goedgekeurde adminaccounts,
   e-mailadressen, en bekende maatwerk-codepaden.
10. **Geen exfiltratie.** Rapporten blijven lokaal en gaan alleen naar het geconfigureerde interne
    adres.

## Detectieniveaus

Detectie kent twee niveaus en die mogen nooit door elkaar lopen:

- **high-confidence**: bevestigde IOC, bijvoorbeeld een hash-match of een bekende webshell-plugin.
  Mag met `--apply` automatisch in quarantaine.
- **heuristic**: generieke obfuscatiepatronen en andere zwakke signalen. Alleen markeren voor
  handmatige review. Nooit automatisch verwijderen.

Legitieme plugins gebruiken `base64_decode` en `gzinflate`. Combineer altijd meerdere signalen
voordat iets high-confidence wordt genoemd. Een IP-match is een signaal, geen bewijs.

`mtime` is onbetrouwbaar: aanvallers zetten timestamps. Gebruik het alleen aanvullend, nooit als
enig signaal.

## Bash-veiligheidsregels

- `set -uo pipefail` in het entrypoint, bewust **zonder** `-e`. Met `-e` kan een falende site de hele
  run afbreken en kan de exitcode van de subshell niet opgevangen worden, en dan sneuvelt principe 6.
- Per-site isolatie heeft precies een correcte vorm:

  ```
  ( verwerk_site "$site" )
  rc=$?
  ```

  De subshell moet een **losstaande opdracht** zijn en `rc` moet op de volgende regel opgevangen
  worden. Schrijf nooit `( ... ) || afhandelaar` en ook niet `if ! ( ... )`. Door de subshell in een
  conditie te plaatsen zet Bash `set -e` uit voor de hele looptijd ervan, ook wanneer de subshell zelf
  `set -e` opnieuw aanzet. Dat is geverifieerd gedrag en het faalt stil.
- Vertrouw voor kritieke voorwaarden niet op `set -e` maar controleer expliciet. De regel dat er nooit
  opgeschoond wordt zonder geslaagde backup is daarom een expliciete `if ! ensure_backup...; then
  return 1; fi` en geen impliciet neveneffect.
- `grep -q` geeft exitcode 1 als er niets matcht, en bij een malwarescanner is dat het normale geval.
  Vang elke detectie-grep af.
- Padverwerking altijd via `find -print0` met `while IFS= read -r -d ''`. Bestandsnamen in
  klantmappen zijn door aanvallers te kiezen en bevatten spaties, newlines en aanhalingstekens.
- Symlinks nooit blind volgen. Aanvallers planten symlinks om buiten de docroot te komen. Gebruik
  `find -P`, `-xdev` waar passend, en controleer bij verplaatsen naar quarantaine dat het doelpad
  binnen de verwachte boom valt.
- JSON die door aanvallers beinvloede data bevat (bestandsnamen, grep-fragmenten) moet correct
  geescaped worden. Gebruik `jq` als die er is, anders de eigen escapefunctie. Nooit met `echo`
  string-concatenatie JSON bouwen zonder escaping.
- Tijdelijke bestanden via `mktemp`, opruimen via `trap` op EXIT en signalen.
- Lockfile via `flock`, met afhandeling van een verweesde lock.
- Nooit een pad interpoleren in een shellcommando zonder quoting.

## Structuur

```
wp2shell.sh                 entrypoint met subcommands
lib/common.sh               logging, locking, run-as-user, JSON, helpers
lib/discovery.sh            alle WordPress-installaties vinden
lib/version.sh              versie-classificatie
lib/detect.sh               detectie: IOC, heuristiek, logs, checksums
lib/backup.sh               backup engine
lib/quarantine.sh           quarantaine engine met manifest
lib/clean.sh                opschonen
lib/harden.sh               preventie
lib/report.sh               JSON, Nederlandstalige samenvatting, e-mail
config/wp2shell.conf        paden, e-mailadres, allowlists, drempels
config/iocs/hashes.txt      bekende SHA1-hashes
config/iocs/ips.txt         bekende aanvaller-IP's
reports/                    output per run
deploy.sh                   uitrol naar een server
```

Subcommands: `scan` (read-only, standaard), `clean`, `harden`, `report`.

Globale vlaggen: `--apply`, `--site <pad>`, `--user <user>`, `--email <adres>`, `--parallel <n>`,
`--quarantine-dir <pad>`, `--backup-dir <pad>`, `--remove-admins`, `--maintenance`.

Exitcodes weerspiegelen de ernstigste bevinding, zodat cron en monitoring erop kunnen sturen.

## Platformregels

### OpenLiteSpeed

- **`.htaccess` wordt eenmalig gelezen en daarna gecachet voor de levensduur van het proces.**
  OpenLiteSpeed parseert de docroot-`.htaccess` bij het laden van de vhostconfig en elke
  submap-`.htaccess` bij de eerste toegang tot die map. Er is nergens een mtime-hercontrole.
  Gevolg: elke hardeningregel die via SSH wordt weggeschreven doet niets tot er een
  `lswsctrl restart` is geweest. Schrijf daarom eerst alle wijzigingen, dan een enkele graceful
  restart, en verifieer pas daarna. Wie schrijft en meteen met curl verifieert, ziet correcte
  regels als mislukt.
- `.htaccess` wordt alleen gelezen als rewrite aan staat voor de vhost. Detecteer dat, neem het niet aan.
- `<Files>`, `<FilesMatch>`, `php_value` en `Require`/`Deny from` werken niet betrouwbaar. Gebruik
  `RewriteRule` en `RewriteCond`.
- Bewerk de door DirectAdmin beheerde vhostconfig niet met de hand. DirectAdmin overschrijft die bij
  een rewrite. Gebruik ModSecurity of DirectAdmin custom config-includes.
- **Er is geen canoniek ModSecurity-regelpad** op DirectAdmin met OpenLiteSpeed. Er zijn minstens
  vier varianten, afhankelijk van hoe de server gebouwd is, en `include` accepteert wildcards op elke
  positie. Parseer de werkelijk geladen configketen en bewijs bereikbaarheid met een canary-regel
  voordat je rapporteert dat regels actief zijn. Anders meld je containment die er niet is.
- Object cache is geen mitigatie. Behandel het nooit als fix.

### Externe tools

Resolveer `find`, `grep` en `tar` naar absolute paden en controleer dat het de GNU-varianten zijn.
De veiligheidsgaranties rond symlinks hangen daarvan af, en een shellfunctie of een niet-GNU
lookalike verandert die semantiek stil. `grep -R` met hoofdletter volgt symlinks naar buiten de boom
en leest daarmee de data van een andere klant. Gebruik `grep -r` of stuur grep aan vanuit find.

`grep -q` geeft exitcode 1 bij geen match. Voor een malwarescanner is geen match het normale geval,
dus elke detectie-grep moet afgevangen worden met `if grep -q ...; then` of `|| true`. Zonder dat
stopt de scan op de eerste schone site.

### DirectAdmin

- Gebruikers: `/usr/local/directadmin/data/users/`. Domeinen per gebruiker in `domains.list`.
- Docroots: `/home/<user>/domains/<domain>/public_html`, plus subdomein-docroots en `private_html`.
- Logs: `/var/log/httpd/domains/<domain>.log` en `.error.log`, plus de OpenLiteSpeed-locaties.
  Maak logpaden configureerbaar en lees ook geroteerde en gecomprimeerde logs.

### Softaculous

- Aanvullende bron, geen waarheid. De autoritatieve inventarisatie gebeurt op bestandsniveau, zodat
  installaties buiten Softaculous en vergeten subinstallaties ook gevonden worden.
- Wel de plek om auto-upgrade structureel aan te zetten.

## Belangrijkste inhoudelijke valkuil

**Gepatcht is niet schoon.** Elke installatie die tijdens het blootstellingsvenster op een kwetsbare
versie stond en vanaf internet bereikbaar was, moet als mogelijk gecompromitteerd worden behandeld,
ook als de versie inmiddels correct is. Een publieke proof-of-concept leest admin-wachtwoordhashes,
dus voor blootgestelde sites geldt dat credentials bekend kunnen zijn.

## Git-workflow

- Branch: `feat/wp2shell-remediation-toolkit`.
- Logische commits per afgeronde stap.
- Per fase een PR, direct mergen met `main`.
- Kan een PR niet meteen gemerged worden omdat checks nog lopen, controleer dan iedere vijf minuten
  tot mergen kan.
- Commitberichten in het Engels, zonder em dash.
