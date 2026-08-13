# wp2shell-fix

Toolkit die op een DirectAdmin-server met OpenLiteSpeed alle WordPress-installaties inventariseert,
controleert op de wp2shell-infectie, besmette sites opschoont en herbesmetting via dit lek voorkomt.

Dit is een defensieve toolkit. Hij detecteert en herstelt, hij valt niets aan.

## Waar gaat het over

wp2shell is een keten van twee kwetsbaarheden in de WordPress-core:

- **CVE-2026-63030**: route-verwarring in de REST API batch-endpoint. Validatie en uitvoering gebeuren
  in gescheiden loops, waardoor een misvormde subrequest een niet-geautoriseerde request toch laat
  uitvoeren.
- **CVE-2026-60137**: onvoldoende sanitizing van `author__not_in` in `WP_Query`.

Geketend levert dit pre-auth remote code execution op tegen een standaardinstallatie zonder plugins.
Beide zijn op 17 juli 2026 gepatcht en staan in de CISA KEV-lijst.

### Welke versies

| WordPress          | Status                                | Bijwerken naar |
| ------------------ | ------------------------------------- | -------------- |
| 6.9.0 t/m 6.9.4    | volledige RCE-keten                   | 6.9.6          |
| 7.0.0 t/m 7.0.1    | volledige RCE-keten                   | 7.0.3          |
| 6.8.0 t/m 6.8.5    | alleen de SQL-injectie                | 6.8.7          |
| ouder dan 6.8      | niet geraakt door wp2shell            | zie hieronder  |

Twee dingen die vaak misgaan bij deze inschatting:

**De SQL-injectie op 6.8.x is niet direct misbruikbaar.** Volgens NVD en de GitHub Security Advisory
is die alleen te misbruiken wanneer een plugin of thema onvertrouwde invoer aan `author__not_in`
doorgeeft. Op 6.8.x saniteert het REST-schema `author_exclude` naar een integer-array. Pas de
route-verwarring vanaf 6.9 laat een rauwe string door. Een 6.8-site moet dus bijgewerkt worden, maar
is niet standaard gecompromitteerd.

**Gepatcht tegen wp2shell is niet hetzelfde als actueel.** Op 6 augustus 2026 kwam er een tweede,
losstaande securityrelease met twaalf oplossingen, waaronder CVE-2026-64638, een pre-auth XSS met een
pad naar uitvoering van PHP-code. Die is teruggeport naar 22 branches. Een site op 6.9.5 is dus wel
wp2shell-gepatcht maar niet meer actueel. Deze toolkit geeft daarom per site twee oordelen.

### Gepatcht is niet schoon

Elke installatie die tijdens het blootstellingsvenster op een kwetsbare versie stond en vanaf internet
bereikbaar was, moet als mogelijk gecompromitteerd behandeld worden, ook als de versie inmiddels goed
is. Bijwerken sluit het gat, maar verwijdert geen achterdeur die er al stond, en er is publieke
proof-of-concept-code die admin-wachtwoordhashes uitleest.

## Installeren

Draai dit op elke server waar de toolkit moet komen:

```bash
git clone https://github.com/BeuningenIT/wp2shell-fix.git
cd wp2shell-fix
./deploy.sh --install-cron
```

Zonder opties installeert `deploy.sh` op de machine waar je hem draait. Dat moet als root,
want hij schrijft naar `/opt/wp2shell` en `/var`. Met `--dry-run` zie je eerst wat er zou
gebeuren, en dat mag wel zonder root.

Gebruik de https-url en niet de ssh-url, want die vraagt om een sleutel op de server.
`deploy.sh` werkt vanuit de map waarin het script zelf staat, dus draai het vanuit de
uitgepakte repository en niet vanuit een map waar alleen dat ene script ligt.

Wil je vanaf een beheermachine naar een andere server uitrollen, dan kan dat met
`--host`:

```bash
./deploy.sh --install-cron --host web02.beuningenit.nl
```

De toolkit draait per server. Voer `deploy.sh` uit voor elke machine apart.

Benodigd op de server: `php`, GNU `find`, GNU `grep`, `tar`, `sha1sum`, `sha256sum`, `curl`, `flock`
en `base64`. WP-CLI wordt automatisch opgehaald als het ontbreekt. Optioneel en automatisch herkend:
`jq`, `clamscan`, `nice`, `ionice`, ModSecurity en Softaculous.

## Gebruiken

Begin altijd met een scan. Die wijzigt niets.

```bash
/opt/wp2shell/wp2shell.sh scan
```

Beperken tot een klant of een site:

```bash
/opt/wp2shell/wp2shell.sh scan --user klantnaam
/opt/wp2shell/wp2shell.sh scan --site /home/klant/domains/voorbeeld.nl/public_html
```

Opschonen. Zonder `--apply` wordt er nog steeds niets gewijzigd, dan zie je alleen wat er zou gebeuren:

```bash
/opt/wp2shell/wp2shell.sh clean --site /home/klant/domains/voorbeeld.nl/public_html
/opt/wp2shell/wp2shell.sh clean --site /home/klant/domains/voorbeeld.nl/public_html --apply
```

Alle installaties op de server in een keer opschonen:

```bash
/opt/wp2shell/wp2shell.sh clean --apply
```

Elke site wordt afzonderlijk behandeld: eerst een backup, dan opschonen, en daarna een
controlescan. Die controle is het punt waarop een site pas als opgeschoond geldt. Blijft er iets
staan, dan meldt het rapport die site expliciet als nog niet schoon in plaats van als klaar. Een
fout op de ene site stopt de andere sites niet.

Hardening toepassen:

```bash
/opt/wp2shell/wp2shell.sh harden --apply
```

### Subcommando's

| Commando | Wat het doet                                                             |
| -------- | ------------------------------------------------------------------------ |
| `scan`   | Read-only inventarisatie en detectie. Standaard. Weigert `--apply`.       |
| `clean`  | Opschonen. Maakt eerst een backup. Doet niets zonder `--apply`.           |
| `harden` | Preventie toepassen. Wijzigende stappen alleen met `--apply`.             |
| `report` | Resultaten van een eerdere run opnieuw tonen of mailen.                   |

### Belangrijkste vlaggen

| Vlag                     | Betekenis                                                            |
| ------------------------ | -------------------------------------------------------------------- |
| `--apply`                | Schakelt wijzigende acties in. Zonder deze vlag wijzigt niets.       |
| `--site <pad>`           | Beperk tot een installatie.                                          |
| `--user <gebruiker>`     | Beperk tot een DirectAdmin-gebruiker.                                |
| `--remove-admins`        | Sta het verwijderen van verdachte adminaccounts toe. Aparte opt-in.  |
| `--maintenance`          | Site in onderhoudsmodus tijdens het opschonen.                       |
| `--email <adres>`        | Rapportbestemming.                                                   |
| `--no-mail`              | Alleen bestanden schrijven, niet mailen.                             |
| `--quarantine-dir <pad>` | Locatie voor bestanden in quarantaine.                               |
| `--backup-dir <pad>`     | Locatie voor backups.                                                |
| `--verbose`              | Toon debugmeldingen.                                                 |

### Exitcodes

Die weerspiegelen de zwaarste bevinding, zodat cron en monitoring erop kunnen sturen.

| Code | Betekenis                                       |
| ---- | ----------------------------------------------- |
| 0    | geen bevindingen                                |
| 1    | verkeerd gebruik                                |
| 2    | interne fout                                    |
| 3    | er draait al een run                            |
| 10   | alleen informatieve bevindingen                 |
| 20   | lage ernst                                      |
| 30   | middelhoge ernst, handmatige review nodig       |
| 40   | hoge ernst, kwetsbare versie of blootstelling   |
| 50   | kritiek, bevestigde compromittering             |

## Hoe veilig dit werkt

Deze toolkit raakt live klantensites. Daarom:

**Rapporteren tenzij je expliciet anders vraagt.** `scan` weigert `--apply` zelfs als je die meegeeft.
`clean` en `harden` doen zonder `--apply` niets anders dan vertellen wat ze zouden doen.

**Backup vooraf, verplicht.** Voor elke wijziging gaan bestanden en database in een backup buiten de
docroot. Mislukt dat, dan wordt die site overgeslagen en gaat het opschonen niet door. Dat is een
expliciete controle, geen neveneffect.

**Quarantaine in plaats van verwijderen.** Niets wordt hard verwijderd. Verdachte bestanden gaan naar
een quarantainemap met behoud van hun relatieve pad, plus een manifest met het oorspronkelijke pad,
beide hashes, grootte, tijdstip en de reden. Terugzetten kan vanuit dat manifest.

**Twee detectieniveaus, streng gescheiden.** Alleen bevestigde bevindingen kunnen met `--apply`
automatisch in quarantaine. Heuristische signalen worden uitsluitend gemarkeerd. Legitieme plugins
gebruiken ook `base64_decode` en `gzinflate`, dus een enkel zwak signaal leidt nooit tot een actie.

**Adminaccounts nooit zomaar weg.** Verdachte beheerders worden standaard alleen gerapporteerd.
Verwijderen vereist naast `--apply` ook `--remove-admins`, content wordt hertoegewezen aan een
beheerder van de allowlist, en zonder veilig doelwit gebeurt er niets.

**Per site geisoleerd.** Een fout op een site stopt de rest niet. Die site krijgt een eigen foutstatus
in het rapport en geldt uitdrukkelijk niet als schoon.

**Eenmalig tegelijk.** Een lockfile voorkomt dat twee runs elkaar in de weg zitten. De tweede stopt
met exitcode 3.

## Rapporten

Elke run schrijft naar `/var/log/wp2shell/reports/<run-id>/`:

| Bestand             | Inhoud                                            |
| ------------------- | ------------------------------------------------- |
| `samenvatting.txt`  | Nederlandstalige samenvatting, ook de mailtekst    |
| `report.json`       | Machineleesbaar, alle sites en bevindingen         |
| `findings.ndjson`   | Bevindingen, een JSON-object per regel             |
| `sites.ndjson`      | Gevonden installaties met versie en classificatie  |
| `audit.log`         | Elke wijziging met hash en reden                   |
| `run.log`           | Volledig runlogboek                                |

## Wat je zelf moet doen na een besmetting

Dit script kan geen wachtwoorden in panelen invoeren. Bij een bevestigde of vermoede compromittering
is `wp-config.php` uitleesbaar geweest, inclusief databasegegevens en API-sleutels. Vervang met de
hand:

- het databasewachtwoord
- de DirectAdmin-login van de klant
- FTP- en SSH-toegang
- elke API-sleutel die in `wp-config.php` stond

Forceer daarnaast een wachtwoordreset voor alle beheerders. De salts en keys worden wel automatisch
vervangen door `harden --apply`, waarmee alle sessies ongeldig worden.

## Aandachtspunten op deze omgeving

**OpenLiteSpeed leest `.htaccess` maar een keer.** Het bestand wordt bij het laden van de configuratie
ingelezen en daarna gecachet zolang het proces leeft. Hardeningregels doen dus niets tot de webserver
herstart is. De toolkit schrijft daarom eerst alle wijzigingen, herstart daarna een keer, en
controleert pas dan. Die controle gebeurt met een proberegel: geeft die 403, dan leest OpenLiteSpeed
de `.htaccess` van die vhost echt.

**Geen `<Files>` of `php_value`.** OpenLiteSpeed ondersteunt die niet betrouwbaar. Alle regels zijn
daarom `RewriteRule`.

**Object cache is geen oplossing.** Redis of Memcached haalt hooguit het RCE-pad weg, niet de
SQL-injectie. LiteSpeed Cache paginacaching is sowieso geen persistente object cache.

**Voor de eerste echte run.** De DirectAdmin- en Softaculous-paden zijn afgeleid uit documentatie en
niet op een draaiende server geverifieerd. Draai op een productieserver eerst `wp2shell.sh scan` en
controleer of het aantal gevonden installaties klopt, voordat je `--apply` gebruikt.

## Ontwikkelen

```bash
./tools/lint.sh
for t in tests/*.sh; do "$t"; done
```

`tools/lint.sh` draait shellcheck, controleert dat er nergens een em dash of en dash staat, en faalt
op elke commentaarregel behalve de shebang. Die conventies staan in `CLAUDE.md`.
