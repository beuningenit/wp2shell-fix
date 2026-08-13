#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wpscan.py - WordPress-vlootscanner voor DirectAdmin-servers.

Draait als root op de server zelf. Zoekt alle WordPress-installaties van alle
DirectAdmin-users, vergelijkt ze met de officiele pakketten van wordpress.org,
scant de rest op malware-handtekeningen, en vergelijkt de sites onderling.

DEZE VERSIE SCHRIJFT NIETS IN /home. Hij leest alleen en schrijft een rapport
plus twee shell-scripts (opruimen.sh / terugzetten.sh) die je zelf nakijkt
voordat je ze draait.

Gebruik:
    python3 wpscan.py                 vraagt interactief wat er gescand wordt
    python3 wpscan.py --user klant01  alleen die user
    python3 wpscan.py --all --yes     alles, zonder vragen (voor in cron)
    python3 wpscan.py --lijst         toon alleen wat er gevonden is, scan niet

Alleen de Python-standaardbibliotheek. Geen pip install nodig.
"""

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from collections import defaultdict

# ---------------------------------------------------------------------------
# Instellingen
# ---------------------------------------------------------------------------

DA_USERS_DIR = '/usr/local/directadmin/data/users'
HOME_DIR = '/home'
WORK_DIR = '/root/wpscan'
CACHE_DIR = os.path.join(WORK_DIR, 'cache')

HTTP_TIMEOUT = 60
USER_AGENT = 'wpscan/1.0 (+serveronderhoud)'

# Bestanden groter dan dit worden alleen gedeeltelijk gescand.
FULL_SCAN_MAX = 8 * 1024 * 1024
PARTIAL_SCAN_BYTES = 512 * 1024

# Extensies die als PHP worden uitgevoerd.
PHP_EXT = ('.php', '.php3', '.php4', '.php5', '.php7', '.php8', '.phtml',
           '.phar', '.pht', '.phps')

# Extensies die we sowieso op handtekeningen scannen.
TEXTUAL_EXT = PHP_EXT + ('.js', '.html', '.htm', '.inc', '.txt', '.ini')

# Mappen die we overslaan: te groot en zelden relevant. Cachemappen staan hier
# bewust NIET bij: malware verstopt zich daar juist graag.
SKIP_DIRS = {'node_modules', '.git', '.svn', '.hg'}

# Handtekeningen. Score >= 8 => Critical, >= 5 => High, >= 3 => Medium, rest Low.
# Overgenomen uit wp-scan.ps1 zodat beide tools hetzelfde vinden.
SIGNATURES = [
    ('eval() op gedecodeerde string', 10,
     r'eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode|urldecode|hex2bin|pack)\s*\(', None),
    ('Decode van gebruikersinvoer', 10,
     r'(base64_decode|gzinflate|gzuncompress|str_rot13|hex2bin)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|SERVER)', None),
    ('assert() op gebruikersinvoer', 10,
     r'assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)', None),
    ('Functie-aanroep vanuit invoer', 9,
     r'\$_(POST|GET|REQUEST|COOKIE)\s*\[[^\]]{0,40}\]\s*\(', None),
    ('Variabele superglobal ($$_POST)', 9,
     r'\$\{\s*[\'"]_(POST|GET|REQUEST|COOKIE|SERVER)', None),
    ('preg_replace met /e modifier', 9,
     r'preg_replace\s*\(\s*([\'"]).{1,80}?[/#~!]\w{0,5}e\w{0,5}\1', None),
    ('Code-include vanuit afbeelding/tekstbestand', 9,
     r'@?\s*(include|require)(_once)?\s*\(?\s*[\'"][^\'"]{0,120}\.(jpe?g|png|gif|ico|bmp|webp|txt|log|csv|dat|css|woff2?)[\'"]', None),
    ('Omgekeerde functienamen (obfuscatie)', 9,
     r'edoced_46esab|etalfnizg|ssergnocnuzg|31tor_rts|noitcnuf_etaerc', None),
    ('auto_prepend/append_file', 9,
     r'auto_(prepend|append)_file', None),
    ('Lange hex-escape reeks', 8,
     r'(\\x[0-9a-fA-F]{2}){24,}',
     r'\\x47\\x49\\x46\\x38\\x39\\x61|\\x89\\x50\\x4e\\x47|\\xff\\xd8\\xff'),
    ('Zelfherstellende dropper (copy naar wp-content)', 10,
     r'@?\s*copy\s*\(\s*[\'"][^\'"]{4,}[\'"]\s*,\s*[\'"][^\'"]*(wp-content|wp-includes|wp-admin)[^\'"]*\.ph(p\d?|tml)[\'"]', None),
    ('Injectiemarkering /*wpt*/', 9,
     r'/\*wpt\*/', None),
    ('Verwijzing naar pad buiten de webroot', 6,
     r'[\'"]/(home|var|usr)/[^\'"]*/(private_html|\.\w+)/[^\'"]*[\'"]', None),
    ('Hex-decodering met chr(hexdec())', 8,
     r'chr\s*\(\s*hexdec\s*\(', None),
    ('Lange hex-string (verborgen payload)', 7,
     r'[\'"][0-9a-f]{120,}[\'"]', None),
    ('Functienaam opgebouwd uit losse stukjes', 8,
     r'(\$\w{1,3}\s*=\s*[\'"][^\'"]{1,4}[\'"]\s*;\s*){5,}', None),
    ('Payload van externe code-hosting', 7,
     r'(raw\.githubusercontent\.com|gist\.github(usercontent)?\.com|pastebin\.com/raw|paste\.ee|transfer\.sh|bitbucket\.org/[^\s\']+/raw)', None),
    # 'MARIJUANA' stond hier ook in, maar dat is de naam van een Font
    # Awesome-icoon en komt dus voor in elke icon-picker. Een echte MARIJUANA-
    # shell raakt sowieso een handvol van de regels hierboven.
    ('Bekende webshell-signatuur', 10,
     r'FilesMan|b374k|c99shell|r57shell|WSO\s*\d|IndoXploit|Mini\s*Shell|Priv8|Bypass\s*Shell|AnonymousFox|alfashell|GEL4Y|wp-file-manager-shell|by\s*Xleet', None),
    ('eval()', 7, r'\beval\s*\(', None),
    ('Geketende chr()-opbouw', 7,
     r'chr\s*\(\s*\d{1,3}\s*\)\s*\.\s*chr\s*\(', None),
    ('pack("H*") decodering', 7, r'\bpack\s*\(\s*[\'"]H\*', None),
    ('Wegschrijven van PHP-bestand', 6,
     r'(file_put_contents|fwrite|fputs)\s*\([^;]{0,160}\.ph(p\d?|tml)', None),
    ('Aanroep via $GLOBALS', 6,
     r'\$GLOBALS\s*\[\s*[\'"][^\'"]{1,12}[\'"]\s*\]\s*\(', None),
    ('create_function()', 6, r'\bcreate_function\s*\(', None),
    ('Zeer lange base64-blob', 6,
     r'[\'"][A-Za-z0-9+/]{280,}={0,2}[\'"]', None),
    # De oude versie eiste het label aan het begin van een regel. Deze
    # obfuscators persen het hele bestand op een regel, dus dan matcht er
    # niets. Nu volstaat een label direct na een ';', '{' of '}'. Echte PHP
    # gebruikt goto vrijwel nooit; in combinatie met wartaalnamen is het
    # sluitend bewijs.
    ('goto-obfuscatie', 8,
     r'\bgoto\s+[A-Za-z_]\w{2,}\s*;[\s\S]{0,400}?[;{}]\s*[A-Za-z_]\w{2,}:',
     None),
    # @eval($f[3]($payload)) -- de functie komt uit een array met versleutelde
    # namen. Geen enkele echte toepassing evalueert zoiets.
    ('eval() van een functie uit een array', 10,
     r'eval\s*\(\s*@?\$\w+\s*\[[^\]]{0,20}\]\s*\(', None),
    # ${$var[41]}[16] -- een superglobal aanroepen via een berekende naam,
    # zodat er nergens $_POST of $_GET in het bestand staat.
    ('Superglobal via een berekende naam', 8,
     r'\$\{\s*\$\w+\s*(\[[^\]]{0,20}\])?\s*\}\s*\[', None),
    # $f[1 + 4] -- rekenen in een array-index heeft geen enkel doel behalve
    # het bemoeilijken van lezen.
    ('Zinloos rekenwerk in een array-index', 7,
     r'\$\w+\s*\[\s*\d{1,4}\s*\+\s*\d{1,4}\s*\]', None),
    # De twee lookbehinds sluiten methodes uit: '$this->system(', '::system('
    # en 'function system(' zijn doodgewone code. Zonder die grens meldt elke
    # class met een methode system() zich als shell-uitvoering.
    ('Shell-uitvoering', 5,
     r'(?<![\w>$:])(?<!function )'
     r'(shell_exec|passthru|proc_open|popen|pcntl_exec|system)\s*\(', None),
    ('Externe code ophalen en uitvoeren', 5,
     r'(curl_exec|file_get_contents)\s*\(\s*[\'"]?https?://[^;]{0,200}(eval|assert|include)', None),
    ('Directe uitvoer via backticks', 5, r'=\s*`[^`\r\n]{3,}`\s*;', None),
    ('Verborgen upload-handler', 4, r'move_uploaded_file\s*\(', None),
    # Een echte uploadfunctie hoeft zijn foutmeldingen niet te verbergen. De
    # combinatie van die twee is het verschil tussen een contactformulier en
    # een uploadshell.
    ('Upload-shell met onderdrukte fouten', 9,
     r'error_reporting\s*\(\s*0\s*\)[\s\S]{0,600}?\$_FILES'
     r'|\$_FILES[\s\S]{0,600}?error_reporting\s*\(\s*0\s*\)', None),
    # Doelpad opgebouwd uit de bestandsnaam die de bezoeker zelf meestuurt,
    # met ../ ervoor: dat is geen upload maar een plaatsingskeuze.
    ('Upload naar een pad uit het verzoek', 9,
     r'[\'"]\.\.?/[\'"]\s*\.\s*\$_FILES', None),
    ('Foutmeldingen onderdrukt + tijdslimiet uit', 3,
     r'(error_reporting\s*\(\s*0\s*\)[\s\S]{0,200}set_time_limit\s*\(\s*0\s*\)|set_time_limit\s*\(\s*0\s*\)[\s\S]{0,200}error_reporting\s*\(\s*0\s*\))', None),
    ('strrev()-obfuscatie', 3, r'\bstrrev\s*\(', None),
    ('Verborgen admin-aanmaak', 8,
     r'wp_(insert|create)_user\s*\([\s\S]{0,300}(administrator|add_role)', None),
    ('Ongefilterde eval van cookie', 10,
     r'\$_COOKIE\s*\[[^\]]{0,40}\]\s*[\s\S]{0,80}(eval|assert|system)\s*\(', None),
]

# JavaScript krijgt zijn eigen, veel kleinere set. De PHP-handtekeningen
# hierboven ('eval(', lange base64, lange hex) staan in ELK geminificeerd
# JS-bestand: LiteSpeed-cache, Elementor, jQuery-bundles. Daar los op scannen
# levert honderden valse treffers op en zou je zomaar een plugin laten
# weggooien. Dit zijn patronen die in normale JS niet voorkomen.
JS_SIGNATURES = [
    ('Eval van gedecodeerde string', 9,
     r'\b(eval|Function)\s*\(\s*(atob|unescape|decodeURIComponent)\s*\(', None),
    ('JS-packer obfuscatie', 8,
     r'eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,', None),
    ('document.write(unescape())', 8,
     r'document\.write\s*\(\s*unescape\s*\(', None),
    ('atob() gevolgd door eval()', 8,
     r'atob\s*\([^)]{0,200}\)[\s\S]{0,150}\beval\s*\(', None),
    ('Lange keten van fromCharCode', 7,
     r'(String\.fromCharCode\s*\([^)]{1,40}\)\s*\+\s*){6,}', None),
    ('PHP-code in een JS-bestand', 9, r'<\?php\s', None),
    ('Bekende injectie-/skimmerdomeinen', 9,
     r'google-analitycs|googie-analytics|jquery-cdn\.(com|net)'
     r'|cdn\.jsdelivr\.net/npm/[a-f0-9]{20,}|statcounter\.help', None),
]

# Vooraf compileren; dat scheelt bij een miljoen bestanden erg veel tijd.
_SIG_RX = [(naam, score, re.compile(rx, re.I | re.M),
            re.compile(x, re.I) if x else None)
           for naam, score, rx, x in SIGNATURES]
_JS_RX = [(naam, score, re.compile(rx, re.I | re.M), None)
          for naam, score, rx, _ in JS_SIGNATURES]

# Handtekeningen die op verhulling wijzen, niet op het losse voorkomen van een
# functienaam. Alleen deze tellen in datamappen en vendor-mappen.
STRUCTURAL = {
    'eval() op gedecodeerde string', 'Decode van gebruikersinvoer',
    'assert() op gebruikersinvoer', 'Functie-aanroep vanuit invoer',
    'Variabele superglobal ($$_POST)', 'preg_replace met /e modifier',
    'Code-include vanuit afbeelding/tekstbestand',
    'Omgekeerde functienamen (obfuscatie)', 'Lange hex-escape reeks',
    'Hex-decodering met chr(hexdec())', 'Geketende chr()-opbouw',
    'Functienaam opgebouwd uit losse stukjes', 'pack("H*") decodering',
    'Ongefilterde eval van cookie', 'Verborgen admin-aanmaak',
    'Zelfherstellende dropper (copy naar wp-content)',
    'Injectiemarkering /*wpt*/',
}

# Deze regel geeft Critical op de NAAM alleen, zonder naar de inhoud te kijken.
# Daarom staan er uitsluitend namen in die nergens anders voorkomen. Eerder
# stonden hier ook 'radio', 'uploader', 'mini', 'up', 'shell', 'cmd' en 'hax'
# bij: dat leverde negen valse treffers op in een doodgewone Joomla, waar
# radio.php een formulierveld is en uploader.php van Fabrik komt. Zulke namen
# vangen we nu via de handtekeningen in de inhoud.
BAD_NAME_RX = re.compile(
    r'^(wp-l0gin|wp-logln|wp-admnn|wp-headre|wp-lock|wp-temp'
    r'|wp-conf(?!ig\.)[a-z0-9]{2,}|wp-inc(?!ludes\.)[a-z0-9]{2,}'
    r'|reviall|adminfuns|alfa|alfanew|wso|sh3ll'
    r'|priv8|indoxploit|b374k|c99shell|r57shell|ak47|gel4y'
    r'|adminer|dbdump|xmrlpc|class-wp-cache)'
    r'\.(php|phtml|php[3578]|txt)$', re.I)

# Mappen met gegenereerde statistieken. Een awstats-pagina met '404 errors'
# somt op welke URL's er zijn opgevraagd -- inclusief elke scanpoging naar
# /wso.php en /alfa.php. Die namen staan er dus in omdat de aanval is GELOGD,
# niet omdat het bestand besmet is. De html slaan we over; een php-bestand in
# zo'n map wordt juist volledig gescand, want dat hoort er sowieso niet.
RAPPORT_RX = re.compile(r'(^|/)(awstats|webalizer|webstats|stats)/', re.I)

# Logboeken die toevallig op .php eindigen. Akeeba schrijft ze zo weg zodat ze
# niet via de browser te lezen zijn; ze beginnen met een die() en bevatten
# verder tekst. Daar tellen alleen handtekeningen die op verhulling wijzen.
LOGBESTAND_RX = re.compile(r'\.log\.php$|(^|/)error_log$', re.I)

# Let op: hoofdlettergevoelig. Zonder dat matcht [A-Z0-9]{5,12} ook 'akismet'.
RANDOM_DIR_RX = [
    re.compile(r'^[a-f0-9]{16,}$'),
    re.compile(r'^(?=.*[0-9])[A-Z0-9]{5,12}$'),
    re.compile(r'^[a-z0-9]+_[a-f0-9]{6,}$'),
    re.compile(r'^[a-z-]+-(?=.*[0-9])[a-f0-9]{6}$'),
    re.compile(r'^[a-z]{1,3}[0-9]{4,}$'),
]

DATA_FILE_RX = re.compile(
    r'^(wp-content/languages/.*\.l10n\.php'
    r'|wp-content/wflogs/(rules|config-[a-z]+|attack-data|ips|template)\.php)$')

# Bibliotheken die van huis uit dingen doen die op malware lijken: getID3 roept
# helper-programma's aan met backticks, de TinyMCE-spellingcontrole draait
# shell_exec op aspell, en pdf-bibliotheken bouwen binaire structuren met
# chr(hexdec()). Ze krijgen dezelfde behandeling als een vendor-map: alleen
# handtekeningen die op verhulling wijzen, en nooit hoger dan High.
VENDOR_RX = re.compile(
    r'/(vendor|vendor_prefixed|node_modules'
    r'|getid3|tiny_?mce|phpmailer|simplepie|htmlpurifier|phpseclib'
    r'|swiftmailer|smarty|adodb|phpthumb|tcpdf|dompdf|fpdf|mpdf'
    r'|phpexcel|phpspreadsheet|guzzle|psr|composer)/', re.I)

# Bestanden die de webserver nooit uitvoert. Oude code in een .txt naast een
# plugin is rommel van de bouwer, geen achterdeur: er moet eerst iets zijn dat
# hem includet, en daar hebben we een eigen handtekening voor.
NIET_UITVOERBAAR = ('.txt', '.md', '.log', '.csv')

PAKKETPAD_RX = re.compile(r'^wp-content/(plugins|themes)/([^/]+)/')

# Mappen waar een kryptische naam niets betekent. De kern vergelijken we toch
# al bestand voor bestand met het origineel, en in uploads zijn jaartallen en
# hashmappen (Elementor-templatekits bijvoorbeeld) de normaalste zaak.
GEEN_MAPNAAMCHECK = ('wp-admin/', 'wp-includes/', 'wp-content/uploads/',
                     'wp-content/upgrade/', 'wp-content/languages/',
                     'wp-content/ai1wm-backups/', 'wp-content/backups')

# Normale thema-/pluginbestanden. Malware hierin is een INJECTIE in een bestand
# dat moet blijven staan; weghalen breekt de site.
# Zonder deze bestanden draait de site niet. Ontbreken ze, dan is dat vrijwel
# altijd het gevolg van een opruimactie die te ruw was: een virusscanner die
# een geinfecteerd kernbestand niet schoonmaakte maar gewoon weghaalde.
KERNBESTANDEN = [
    'index.php', 'wp-blog-header.php', 'wp-load.php', 'wp-settings.php',
    'wp-login.php', 'wp-cron.php', 'wp-comments-post.php',
    'wp-includes/functions.php', 'wp-includes/version.php',
    'wp-includes/load.php', 'wp-includes/template-loader.php',
    'wp-admin/index.php', 'wp-admin/admin.php', 'wp-admin/admin-ajax.php',
]

# Bestandsnamen die bij WordPress zelf horen. Zet iemand die op de witte lijst
# in een .htaccess, dan is dat om de site werkend te houden -- dat doet een
# beveiligingsplugin net zo goed als een aanvaller. Deze namen zeggen dus niets
# over een achterdeur, en ze najagen betekent de halve kern opruimen.
WP_KERNNAMEN = {
    'index.php', 'wp-activate.php', 'wp-blog-header.php',
    'wp-comments-post.php', 'wp-config.php', 'wp-config-sample.php',
    'wp-cron.php', 'wp-links-opml.php', 'wp-load.php', 'wp-login.php',
    'wp-mail.php', 'wp-settings.php', 'wp-signup.php', 'wp-trackback.php',
    'xmlrpc.php', 'admin.php', 'admin-ajax.php', 'admin-post.php',
    'admin-header.php', 'admin-footer.php', 'admin-functions.php',
    'load-scripts.php', 'load-styles.php', 'async-upload.php',
    'media-upload.php', 'upgrade.php', 'install.php', 'setup-config.php',
    'ms-files.php', 'wp-tinymce.php', 'wp-emoji-release.min.php',
}

LEGIT_NAMES = {
    'functions.php', 'index.php', 'header.php', 'footer.php', 'sidebar.php',
    'single.php', 'page.php', 'archive.php', 'search.php', '404.php',
    'comments.php', 'front-page.php', 'home.php', 'category.php', 'tag.php',
    'author.php', 'date.php', 'attachment.php', 'image.php', 'taxonomy.php',
    'searchform.php', 'template-functions.php', 'wp-config.php',
}

# Verdachte patronen in crontabs.
CRON_BAD_RX = re.compile(
    r'(curl|wget|fetch)[^\n|]*\|\s*(ba)?sh'
    r'|base64\s+-d|php\s+-r|/tmp/\S|/dev/shm/\S|\.onion|nc\s+-e'
    r'|python\s+-c|perl\s+-e', re.I)


# ---------------------------------------------------------------------------
# Terminal
# ---------------------------------------------------------------------------

_COLOR = sys.stdout.isatty() and os.environ.get('TERM') not in (None, 'dumb')

_KLEUREN = {
    'rood': '91', 'oranje': '38;5;208', 'geel': '93', 'groen': '92',
    'blauw': '96', 'grijs': '90', 'vet': '1',
}


def c(tekst, kleur):
    if not _COLOR:
        return tekst
    return '\033[%sm%s\033[0m' % (_KLEUREN[kleur], tekst)


def kop(tekst):
    print('')
    print(c('=' * 74, 'blauw'))
    print(c(' ' + tekst, 'blauw'))
    print(c('=' * 74, 'blauw'))


def sev_kleur(sev):
    return {'Critical': 'rood', 'High': 'oranje', 'Medium': 'blauw',
            'Low': 'grijs', 'Info': 'grijs'}.get(sev, 'grijs')


# Wordt gezet zodra de invoer op is. Zonder dit blijft een vraag-lus eeuwig
# doordraaien als het script zonder terminal wordt gestart.
_INVOER_OP = [False]


def vraag(prompt, standaard=''):
    """Read-Host met nette afhandeling van Ctrl-C en niet-interactieve invoer."""
    if _INVOER_OP[0]:
        return standaard
    try:
        antwoord = input(prompt)
    except EOFError:
        _INVOER_OP[0] = True
        print('')
        return standaard
    # Ctrl-C laten we bewust doorgaan naar boven: dat betekent stoppen, niet
    # 'ga verder met de standaardkeuze'.
    return antwoord.strip()


def kort(tekst, n):
    """Een regel op lengte brengen; plet ook regeleindes en dubbele spaties."""
    tekst = ' '.join((tekst or '').split())
    return tekst if len(tekst) <= n else tekst[:n - 3] + '...'


def mensbytes(n):
    for eenheid in ('B', 'kB', 'MB', 'GB'):
        if n < 1024 or eenheid == 'GB':
            return '%.0f %s' % (n, eenheid) if eenheid == 'B' else '%.1f %s' % (n, eenheid)
        n /= 1024.0
    return str(n)


# ---------------------------------------------------------------------------
# Hashes en HTTP
# ---------------------------------------------------------------------------

def hash_bestand(pad, algo='md5'):
    h = hashlib.new(algo)
    try:
        with open(pad, 'rb') as f:
            for blok in iter(lambda: f.read(1024 * 256), b''):
                h.update(blok)
    except (IOError, OSError):
        return None
    return h.hexdigest()


def hash_beide(pad):
    """Md5 en sha256 in een keer, zodat we het bestand maar een keer lezen."""
    m, s = hashlib.md5(), hashlib.sha256()
    try:
        with open(pad, 'rb') as f:
            for blok in iter(lambda: f.read(1024 * 256), b''):
                m.update(blok)
                s.update(blok)
    except (IOError, OSError):
        return None, None
    return m.hexdigest(), s.hexdigest()


def http_json(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            return json.loads(r.read().decode('utf-8', 'replace'))
    except Exception:
        return None


def http_bestand(url, doel):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            data = r.read()
        if len(data) < 200:
            return False
        with open(doel, 'wb') as f:
            f.write(data)
        return True
    except Exception:
        return False


def veilig_uitpakken(zippad, doelmap):
    """Pakt uit met bescherming tegen ../-paden in het archief."""
    try:
        with zipfile.ZipFile(zippad) as z:
            for lid in z.namelist():
                doel = os.path.realpath(os.path.join(doelmap, lid))
                if not doel.startswith(os.path.realpath(doelmap) + os.sep):
                    return False
            z.extractall(doelmap)
        return True
    except Exception:
        return False


_pakket_cache = {}


def haal_pakket(url, sleutel):
    """
    Haalt een zip op en pakt hem uit in de gedeelde cache. Geeft het pad terug,
    of None. De cache wordt over alle sites gedeeld: elke plugin wordt hooguit
    een keer gedownload, ook als hij op dertig sites staat.
    """
    if sleutel in _pakket_cache:
        return _pakket_cache[sleutel]

    uitpakmap = os.path.join(CACHE_DIR, sleutel)
    if os.path.isdir(uitpakmap) and os.listdir(uitpakmap):
        _pakket_cache[sleutel] = uitpakmap
        return uitpakmap

    zippad = os.path.join(CACHE_DIR, sleutel + '.zip')
    if not os.path.exists(zippad):
        if not http_bestand(url, zippad):
            _pakket_cache[sleutel] = None
            return None

    os.makedirs(uitpakmap, exist_ok=True)
    if not veilig_uitpakken(zippad, uitpakmap):
        shutil.rmtree(uitpakmap, ignore_errors=True)
        _pakket_cache[sleutel] = None
        return None

    _pakket_cache[sleutel] = uitpakmap
    return uitpakmap


def pakket_hashes(pakketmap, submap):
    """
    Bouwt ({relatiefpad: md5}, basismap) van een uitgepakt officieel pakket.
    Een plugin-zip bevat een map met de slug erin; die halen we eraf. De
    basismap geven we terug zodat we later het schone bestand kunnen
    terugkopieren.
    """
    basis = os.path.join(pakketmap, submap)
    if not os.path.isdir(basis):
        # Sommige zips pakken direct uit zonder submap.
        inhoud = [d for d in os.listdir(pakketmap)
                  if os.path.isdir(os.path.join(pakketmap, d))]
        if len(inhoud) == 1:
            basis = os.path.join(pakketmap, inhoud[0])
        else:
            basis = pakketmap

    resultaat = {}
    for wortel, mappen, bestanden in os.walk(basis):
        mappen[:] = [m for m in mappen if not os.path.islink(os.path.join(wortel, m))]
        for naam in bestanden:
            vol = os.path.join(wortel, naam)
            if os.path.islink(vol):
                continue
            rel = os.path.relpath(vol, basis).replace(os.sep, '/')
            h = hash_bestand(vol)
            if h:
                resultaat[rel] = h
    return resultaat, basis


# ---------------------------------------------------------------------------
# DirectAdmin-ontdekking
# ---------------------------------------------------------------------------

def da_users():
    """Alle DirectAdmin-users, met /home als terugvaloptie."""
    users = []
    if os.path.isdir(DA_USERS_DIR):
        for naam in sorted(os.listdir(DA_USERS_DIR)):
            if os.path.isdir(os.path.join(DA_USERS_DIR, naam)):
                users.append(naam)
    if not users and os.path.isdir(HOME_DIR):
        for naam in sorted(os.listdir(HOME_DIR)):
            if os.path.isdir(os.path.join(HOME_DIR, naam, 'domains')):
                users.append(naam)
    return users


def domeinen_van(user):
    """Domeinen van een user, uit domains.list of anders van schijf."""
    domeinen = []
    lijst = os.path.join(DA_USERS_DIR, user, 'domains.list')
    if os.path.isfile(lijst):
        try:
            with open(lijst, 'r', errors='replace') as f:
                domeinen = [r.strip() for r in f if r.strip()]
        except (IOError, OSError):
            pass
    if not domeinen:
        basis = os.path.join(HOME_DIR, user, 'domains')
        if os.path.isdir(basis):
            try:
                domeinen = sorted(d for d in os.listdir(basis)
                                  if os.path.isdir(os.path.join(basis, d)))
            except OSError:
                pass
    return domeinen


def inst_naam(inst):
    """
    Hoe deze installatie in lijsten en rapporten heet.

    Een domein levert twee regels op: de WordPress-installatie en de rest van
    de domeinmap eromheen. Zonder onderscheid staan die identiek onder elkaar
    met verschillende cijfers, en dan lijkt het alsof dezelfde site twee keer
    iets anders oplevert.
    """
    naam = inst['domein'] + ('/' + inst['submap'] if inst['submap'] else '')
    if inst.get('soort') != 'los':
        return naam
    return naam + (' (buiten WP)' if inst.get('rest') else ' (geen WP)')


def soort_label(inst):
    """'WP 7.0.2' of wat voor losse map het is, voor in de lijstjes."""
    if inst.get('soort') == 'los':
        if inst.get('rest'):
            return c('rest van het domein, buiten WordPress', 'grijs')
        return c('geen WordPress (alleen handtekeningen)', 'grijs')
    return 'WP %s' % (inst.get('versie') or '?')


STANDAARDTHEMA_RX = re.compile(r'^twenty[a-z]+$', re.I)


def actieve_themas(inst):
    """
    De mapnamen van het actieve thema en, bij een childthema, van zijn ouder.

    Geeft None als we het niet zeker weten. Dat verschil is belangrijk: een
    lege set zou betekenen 'geen enkel thema is actief' en dan zouden we ze
    allemaal weghalen.
    """
    config = os.path.join(inst['root'], 'wp-config.php')
    if not os.path.isfile(config):
        config = os.path.join(os.path.dirname(inst['root']), 'wp-config.php')
        if not os.path.isfile(config):
            return None
    db, prefix = db_gegevens(config)
    if not db:
        return None
    rijen = mysql_rijen(db, "SELECT option_value FROM %soptions WHERE "
                            "option_name IN ('template','stylesheet')" % prefix)
    if not rijen:
        return None
    namen = set(r[0].strip() for r in rijen if r and r[0].strip())
    return namen or None


def wp_versie(wortel):
    pad = os.path.join(wortel, 'wp-includes', 'version.php')
    try:
        with open(pad, 'r', errors='replace') as f:
            tekst = f.read(20000)
    except (IOError, OSError):
        return None
    m = re.search(r"\$wp_version\s*=\s*'([^']+)'", tekst)
    return m.group(1) if m else None


def zoek_wp_installaties(docroot, maxdiepte=4):
    """
    Zoekt WordPress-installaties onder een docroot, inclusief installaties in
    een submap. Volgt geen symlinks: private_html is op DirectAdmin een link
    naar public_html en zou anders alles dubbel scannen.
    """
    gevonden = []
    if not os.path.isdir(docroot) or os.path.islink(docroot):
        return gevonden

    basisdiepte = docroot.rstrip('/').count('/')
    for wortel, mappen, bestanden in os.walk(docroot, followlinks=False):
        if wortel.count('/') - basisdiepte >= maxdiepte:
            mappen[:] = []
            continue
        mappen[:] = [m for m in mappen
                     if m not in SKIP_DIRS
                     and not os.path.islink(os.path.join(wortel, m))]

        if os.path.isfile(os.path.join(wortel, 'wp-includes', 'version.php')):
            versie = wp_versie(wortel)
            gevonden.append({'root': wortel, 'versie': versie})
            # Niet verder zoeken binnen een gevonden installatie.
            mappen[:] = []
    return gevonden


# Andere webapplicaties, aan hun eigen vingerafdruk te herkennen. Bewust
# specifieke bestanden: 'app/' of 'config/' heeft half het internet.
CMS_MARKERS = (
    ('Joomla', ('configuration.php', 'administrator/index.php',
                'libraries/joomla')),
    ('Drupal', ('core/lib/Drupal.php',)),
    ('Drupal 7', ('includes/bootstrap.inc', 'modules/system/system.module')),
    ('Magento', ('app/Mage.php',)),
    ('Magento 2', ('app/etc/env.php', 'bin/magento')),
    ('PrestaShop', ('config/settings.inc.php', 'classes/Shop.php')),
    ('TYPO3', ('typo3/sysext/core/composer.json',)),
    ('phpBB', ('config.php', 'includes/bbcode.php')),
    ('Moodle', ('config.php', 'lib/moodlelib.php')),
)


def zoek_andere_apps(wortel, maxdiepte=3):
    """
    Zoekt niet-WordPress applicaties onder een map.

    Zonder dit is een gearchiveerde Joomla gewoon 'een hoop losse bestanden',
    en dan wordt elk legitiem shell_exec() een reden om een bestand weg te
    zetten. Net als bij een plugin geldt: je haalt er niet zomaar iets uit.
    Geeft [(relatief pad, naam van de applicatie)] terug.
    """
    gevonden = []
    if not os.path.isdir(wortel):
        return gevonden
    basisdiepte = wortel.rstrip('/').count('/')
    for pad, mappen, bestanden in os.walk(wortel, followlinks=False):
        if pad.count('/') - basisdiepte >= maxdiepte:
            mappen[:] = []
            continue
        mappen[:] = [m for m in mappen
                     if m not in SKIP_DIRS
                     and not os.path.islink(os.path.join(pad, m))]
        for naam, sporen in CMS_MARKERS:
            if not all(os.path.exists(os.path.join(pad, *s.split('/')))
                       for s in sporen):
                continue
            rel = os.path.relpath(pad, wortel).replace(os.sep, '/')
            gevonden.append(('' if rel == '.' else rel, naam))
            mappen[:] = []       # niet verder zoeken binnen een applicatie
            break
    return gevonden


def inventariseer(users):
    """Bouwt de volledige inventaris zonder ook maar iets te scannen."""
    inventaris = []
    for user in users:
        installaties = []
        for domein in domeinen_van(user):
            domeinmap = os.path.join(HOME_DIR, user, 'domains', domein)
            if not os.path.isdir(domeinmap) or os.path.islink(domeinmap):
                continue
            docroot = os.path.join(domeinmap, 'public_html')
            wp = zoek_wp_installaties(docroot)
            for inst in wp:
                inst['user'] = user
                inst['domein'] = domein
                inst['soort'] = 'wp'
                submap = os.path.relpath(inst['root'], docroot)
                inst['submap'] = '' if submap == '.' else submap
                installaties.append(inst)

            # De rest van het domein, en dat is bewust de HELE domeinmap en
            # niet alleen public_html. Een bestand als
            # domains/<domein>/filefuns.php staat buiten de webmap en werd zo
            # nooit gezien, terwijl het via een include uit public_html of via
            # auto_prepend_file gewoon meedraait.
            overslaan = [os.path.normpath(i['root']) for i in wp]
            logmap = os.path.join(domeinmap, 'logs')
            if os.path.isdir(logmap):
                overslaan.append(os.path.normpath(logmap))
            installaties.append({
                'root': domeinmap, 'versie': None, 'user': user,
                'domein': domein, 'submap': '', 'soort': 'los',
                'rest': bool(wp), 'overslaan': overslaan,
            })
        if installaties:
            inventaris.append({'user': user, 'installaties': installaties})
    return inventaris


# ---------------------------------------------------------------------------
# Handtekeningen
# ---------------------------------------------------------------------------

def lees_tekst(pad, maxbytes=FULL_SCAN_MAX):
    try:
        grootte = os.path.getsize(pad)
        with open(pad, 'rb') as f:
            ruw = f.read(min(grootte, maxbytes))
    except (IOError, OSError):
        return ''
    return ruw.decode('utf-8', 'replace')


def zoek_handtekeningen(tekst, alleen_structureel=False, javascript=False):
    treffers = []
    for naam, score, rx, uitzondering in (_JS_RX if javascript else _SIG_RX):
        if alleen_structureel and not javascript and naam not in STRUCTURAL:
            continue
        if uitzondering and uitzondering.search(tekst):
            continue
        m = rx.search(tekst)
        if not m:
            continue
        fragment = m.group(0)
        if len(fragment) > 90:
            fragment = fragment[:90] + '...'
        fragment = re.sub(r'[\r\n\t]+', ' ', fragment).strip()
        regel = tekst.count('\n', 0, m.start()) + 1
        treffers.append({'naam': naam, 'score': score,
                         'regel': regel, 'fragment': fragment})
    return treffers


HT_OPEN = re.compile(r'<\s*Files(Match)?\b[^>]*>', re.I)
HT_SLUIT = re.compile(r'<\s*/\s*Files(Match)?\s*>', re.I)
HT_NOEMT_PHP = re.compile(r'ph[p13578]|phtml', re.I)
# Bekende achterdeurnamen in een <Files>-blok: die whitelist zet de aanvaller
# erbij om precies zijn eigen bestand uitvoerbaar te houden.
HT_SLECHTE_NAAM = re.compile(
    r'wp-conf[a-z0-9]{2,}|wp-headre|wp-logln|wp-admnn|wp-lock|wp-temp'
    r'|reviall|adminfuns|alfa|radio|\.suspected', re.I)
HT_GEEFT_TOEGANG = re.compile(
    r'allow\s+from\s+all|require\s+all\s+granted|satisfy\s+any', re.I)
# Let op: 'Order allow,deny' staat hier bewust NIET bij. Dat is alleen de
# volgorde waarin Apache de regels afhandelt, geen weigering op zichzelf; het
# komt net zo goed voor in een blok dat toegang geeft.
HT_WEIGERT = re.compile(
    r'deny\s+from\s+all|require\s+all\s+denied', re.I)
HT_SLECHTE_REGEL = [
    re.compile(r'^\s*php_(admin_)?value\s+auto_(prepend|append)_file', re.I),
    re.compile(r'^\s*php_flag\s+auto_(prepend|append)_file', re.I),
    re.compile(r'^\s*auto_(prepend|append)_file\s*=', re.I),
]


def rare_php_schrijfwijze(tekst):
    """
    Geeft de eerste rare hoofdletterschrijfwijze van 'php' terug, of None.
    'php' en 'PHP' zijn normaal; 'pHp' schrijft niemand per ongeluk. Dit MOET
    hoofdlettergevoelig: met een case-insensitive vergelijking matcht een
    doodnormale <Files *.php> ook, en dat is nu juist een beveiligingsregel
    die moet blijven staan.
    """
    for m in re.finditer(r'[Pp][Hh][Pp]', tekst):
        if m.group(0) not in ('php', 'PHP'):
            return m.group(0)
    return None


def _blok_is_kwaadaardig(tag, blok):
    """
    Beoordeelt een compleet <Files>-blok, niet alleen de openingsregel.

    Doorslaggevend is deny versus allow, NIET de schrijfwijze. Een
    beveiligingsplugin somt net zo goed alle hoofdletter-varianten van php op
    als een aanvaller, want <FilesMatch> is hoofdlettergevoelig. Een blok dat
    uitsluitend toegang weigert beperkt de site en kan dus nooit een
    achterdeur zijn; dat moet blijven staan.
    """
    inhoud = '\n'.join(blok)
    geeft = HT_GEEFT_TOEGANG.search(inhoud)
    weigert = HT_WEIGERT.search(inhoud)

    if weigert and not geeft:
        return None

    if HT_SLECHTE_NAAM.search(tag):
        return 'zet een bekende achterdeurnaam op de witte lijst'

    if geeft and HT_NOEMT_PHP.search(tag):
        # Een beveiligingsplugin blokkeert alle php en zet daarna precies de
        # WordPress-bestanden weer aan die echt aangeroepen moeten worden:
        # admin-ajax.php, wp-tinymce.php. Noemt het blok uitsluitend zulke
        # namen, dan is dit de hardening zelf en niet het slot van de
        # aanvaller. Zonder deze uitzondering haalden we die regels weg en
        # gingen de genoemde kernbestanden er achteraan.
        namen = php_namen_uit_tag(tag)
        if namen and not onbekende_namen(namen):
            return None
        raar = rare_php_schrijfwijze(tag)
        return ('geeft juist toegang tot php-bestanden'
                + (' (schrijfwijze "%s")' % raar if raar else ''))

    return None


NAAM_UIT_TAG_RX = re.compile(r'[\w.-]+\.ph(?:p\d?|tml)', re.I)


def php_namen_uit_tag(tag):
    """
    De php-bestandsnamen die een <Files>-tag noemt, met hoofdletters en al.

    De backslashes gaan er eerst uit, zodat een <FilesMatch "^wp-tinymce\\.php$">
    dezelfde naam oplevert als een <Files wp-tinymce.php>.

    De schrijfwijze blijft staan: op Linux is aSMlkii.php een ander bestand dan
    asmlkii.php, en juist die namen zoeken we straks op schijf.
    """
    schoon = tag.replace('\\', '')
    return set(n.lstrip('.') for n in NAAM_UIT_TAG_RX.findall(schoon))


def onbekende_namen(namen):
    """Welke van deze namen zijn niet van WordPress zelf? Los van hoofdletters."""
    bekend = WP_KERNNAMEN | LEGIT_NAMES
    return set(n for n in namen if n.lower() not in bekend)


def gewhitelist_namen(blok):
    """
    Haalt de bestandsnamen uit een kwaadaardig <Files>-blok.

    Een aanvaller die php overal blokkeert en daarna precies een bestand op de
    witte lijst zet, schrijft daarmee de naam van zijn eigen achterdeur op.
    Die namen kun je vervolgens gericht zoeken, ook op de andere sites.

    Namen van WordPress zelf laten we eruit. Die staan er om de site werkend
    te houden; ze najagen zou betekenen dat we index.php en admin-ajax.php van
    elke site naar quarantaine verplaatsen.
    """
    namen = set()
    for regel in blok:
        if not HT_OPEN.search(regel):
            continue
        namen |= php_namen_uit_tag(regel)
    return onbekende_namen(namen)


def repareer_htaccess(tekst):
    """
    Haalt de kwaadaardige blokken uit een .htaccess en laat de rest staan.
    Een vast standaardblok terugschrijven kan niet: elke site heeft eigen
    SSL-redirects, cacheregels en doorverwijzingen die dan zouden sneuvelen.

    Kijkt naar het hele blok, niet alleen naar de openingsregel: een
    <Files *.php> die toegang WEIGERT is een beveiligingsmaatregel en blijft
    staan; eentje die toegang GEEFT is het slot van de aanvaller.

    Geeft (schone_tekst, [redenen], {namen op de witte lijst}) terug.
    """
    regels = re.split(r'\r?\n', tekst)
    houden, redenen, namen = [], [], set()
    i = 0

    while i < len(regels):
        regel = regels[i]

        open_tag = HT_OPEN.search(regel)
        if open_tag:
            blok, j = [regel], i
            while j < len(regels) and not HT_SLUIT.search(regels[j]):
                j += 1
                if j < len(regels):
                    blok.append(regels[j])
            # Geen sluittag gevonden: dan is het geen blok, laat staan.
            if j >= len(regels):
                houden.append(regel)
                i += 1
                continue
            reden = _blok_is_kwaadaardig(open_tag.group(0), blok)
            if reden:
                redenen.append('%s -- %s' % (regel.strip()[:70], reden))
                namen |= gewhitelist_namen(blok)
            else:
                houden.extend(blok)
            i = j + 1
            continue

        if any(p.search(regel) for p in HT_SLECHTE_REGEL):
            redenen.append(regel.strip()[:80])
            i += 1
            continue

        houden.append(regel)
        i += 1

    schoon = re.sub(r'(\n\s*){3,}', '\n\n', '\n'.join(houden)).strip()
    return schoon, redenen, namen


MARKER_RX = re.compile(r'/\*(\w{2,12})\*/[\s\S]{0,4000}?/\*\1\*/\s*(\?>)?')


def lees_tekst_exact(pad):
    """
    Leest een bestand als strikte UTF-8. Geeft None als dat niet lukt.

    Voor reparaties is dit verplicht. lees_tekst() decodeert met 'replace' en
    dat is prima om in te zoeken, maar als je die tekst terugschrijft is elk
    onleesbaar byte veranderd in een vraagteken en heb je het bestand
    verminkt.
    """
    try:
        with open(pad, 'rb') as f:
            return f.read().decode('utf-8')
    except (IOError, OSError, UnicodeDecodeError):
        return None


def repareer_php(tekst):
    """
    Verwijdert code die in een verder legitiem PHP-bestand is geplakt:
      - een eerste regel met malware voor het echte <?php van het bestand
      - een blok tussen twee identieke markeringen, zoals /*wpt*/ ... /*wpt*/

    De volgorde is niet vrijblijvend: de regel-injectie moet als eerste weg.
    Haal je eerst het gemarkeerde blok eruit, dan blijft de losse <?php van
    regel 1 staan, begint het bestand twee keer met <?php en is het een
    parsefout. Zelfde logica als Repair-InjectedPhpText in wp-scan.ps1.

    Geeft (schone_tekst, verwijderde_stukken) terug.
    """
    verwijderd = []
    uit = tekst

    # 1. De aanvaller plakt een complete regel voor het echte begin van het
    #    bestand. Die hele regel moet weg, niet alleen het kwade deel ervan.
    regels = re.split(r'\r?\n', uit)
    while len(regels) > 1 and re.match(r'^\s*<\?php', regels[0]):
        rest = '\n'.join(regels[1:])
        if not re.search(r'(?m)^\s*<\?php', rest):
            break
        if not zoek_handtekeningen(regels[0]):
            break
        verwijderd.append(regels[0])
        uit = rest
        regels = re.split(r'\r?\n', uit)

    # 2. Gemarkeerde injecties midden in het bestand: /*abc*/ ... /*abc*/.
    while True:
        m = MARKER_RX.search(uit)
        if not m:
            break
        verwijderd.append(m.group(0))
        uit = uit[:m.start()] + uit[m.end():]

    # 3. Een achtergebleven lege openingstag vlak voor de echte openingstag
    #    zou alsnog een parsefout geven.
    uit = re.sub(r'^\s*<\?php\s*(\r?\n\s*)*<\?php', '<?php', uit)
    uit = re.sub(r'^\s*\?>\s*(\r?\n)*', '', uit)

    return uit.lstrip('\r\n '), [r for r in verwijderd if r.strip()]


def sev_van_score(score):
    if score >= 8:
        return 'Critical'
    if score >= 5:
        return 'High'
    if score >= 3:
        return 'Medium'
    return 'Low'


KLINKERS = set('aeiouy')


def lijkt_wartaal(naam):
    """
    Ziet deze plugin- of themanaam eruit alsof er op een toetsenbord gerammeld
    is? Denk aan 'ovhvhwl', 'csktgji' of 'post-core-sp7v'.

    De RANDOM_DIR_RX hierboven vangen alleen de duidelijke gevallen (hex,
    hoofdletters met cijfers). Een aanvaller die kleine letters gebruikt kwam
    daar tot nu toe langs. Deze test kijkt naar de uitspreekbaarheid: elk
    stukje tussen streepjes moet klinkers op redelijke afstand hebben.

    Bewust voorzichtig, want een fout hier zet een echte plugin in quarantaine:
      - 'y' telt als klinker, anders sneuvelt 'blocksy'
      - pas vanaf vijf medeklinkers op rij, anders sneuvelt 'bbpress'
      - een stuk zonder enige klinker moet ook nog een cijfer bevatten,
        anders sneuvelt 'wpml'
    Deze test wordt alleen gebruikt als wordpress.org de map niet kent, dus
    'bbpress' en 'blocksy' zouden sowieso al buiten schot blijven.
    """
    for stuk in re.split(r'[-_. ]+', naam.lower()):
        if len(stuk) < 4 or not re.match(r'^[a-z0-9]+$', stuk):
            continue
        reeks = langste = 0
        for teken in stuk:
            if teken in KLINKERS:
                reeks = 0
            else:
                reeks += 1
                langste = max(langste, reeks)
        if langste >= 5:
            return True
        if langste == len(stuk) and re.search(r'[0-9]', stuk):
            return True
    return False


def lijkt_wartaal_map(naam):
    """
    Strengere variant van lijkt_wartaal() voor gewone mapnamen.

    Pluginslugs zijn door mensen bedacht; mapnamen zijn dat lang niet altijd.
    Jaartallen (2016), afkortingen (l10n, Psr7), versies (PHP52) en hashes zijn
    volstrekt normaal, en gewone woorden hebben soms vijf medeklinkers op rij
    ('fullscreen', 'lightgray'). Daarom eist deze test echte letters zonder
    klinkers: 'ovhvhwl' en '1qzfxbj' wel, de rest niet.
    """
    n = naam.lower()
    if not re.match(r'^[a-z0-9]{5,12}$', n):
        return False
    letters = [t for t in n if t.isalpha()]
    if len(letters) < 4:
        return False              # '2016', 'l10n', 'php52': te weinig letters
    klinkers = [t for t in letters if t in KLINKERS]
    if not klinkers:
        return True
    if len(klinkers) > 1:
        return False              # 'fullscreen', 'curve25519': uitspreekbaar
    reeks = langste = 0
    for teken in n:
        if teken in KLINKERS:
            reeks = 0
        else:
            reeks += 1
            langste = max(langste, reeks)
    return langste >= 5


def is_legitiem(rel, laag):
    """
    Hoort een bestand met deze naam op deze plek te staan?

    De naam alleen is niet genoeg, en dat was lang een gat. 'index.php' hoort
    in de webroot en in een plugin- of themamap. Ligt datzelfde 'index.php' in
    een map als '1qzfxbj/qwegdzh/', dan is het geen injectie in een bestand dat
    moet blijven staan, maar een gedropte shell die toevallig een vertrouwde
    naam draagt. Zonder deze plaatscontrole kwam zulke malware op 'Review'
    terecht en deed opruimen.sh er niets mee.
    """
    if laag not in LEGIT_NAMES:
        return False
    if '/' not in rel:
        return True                   # in de webroot zelf
    m = PAKKETPAD_RX.match(rel)
    if m:
        # Alleen in een THEMA laadt WordPress bestanden op naam: single.php,
        # archive.php en functions.php worden per conventie ingeladen zonder
        # dat iets ernaar verwijst. In een plugin zegt de naam niets; een
        # index.php in een css-map is daar hooguit een lege wachter, en die
        # is hierboven al afgevangen.
        return m.group(1) == 'themes'
    return rel.startswith('wp-admin/') or rel.startswith('wp-includes/')


def hoort_bij_pakket(rel, verdacht=()):
    """
    Zit dit bestand in een plugin- of themamap met een gewone naam? Geeft dan
    'plugins/elementor-pro' terug, anders None.

    Zulke bestanden mag je niet zomaar naar quarantaine verplaatsen: haal je
    er een bestand uit, dan werkt die plugin niet meer. Blijkt het toch echt
    malware, dan is de juiste ingreep het pakket opnieuw installeren.
    Willekeurig genoemde mappen tellen hier niet mee: dat zijn geen plugins.
    """
    m = PAKKETPAD_RX.match(rel)
    if not m:
        return None
    naam = m.group(2)
    if any(rx.match(naam) for rx in RANDOM_DIR_RX):
        return None
    pakket = m.group(1) + '/' + naam
    if pakket in verdacht:
        return None
    return pakket


_PAKKET_INHOUD = {}     # pakketmap -> ([(abspad, inhoud)], compleet gelezen?)
PAKKET_TEKST_EXT = ('.php', '.inc', '.json', '.txt', '.md', '.map', '.js')
PAKKET_LEES_MAX = 24 * 1024 * 1024


def _pakket_inhoud(pakketmap):
    """
    Leest de tekstbestanden van een pakket een keer in en onthoudt ze.

    Zonder deze cache liep de controle hieronder voor elke bevinding opnieuw
    door de hele pluginmap. Bij een pakket als WooCommerce is dat tienduizend
    bestanden, keer op keer. Nu is het een keer lezen per pakket; de cache
    wordt na elke installatie geleegd zodat het geheugen niet oploopt.
    """
    if pakketmap in _PAKKET_INHOUD:
        return _PAKKET_INHOUD[pakketmap]
    delen, totaal, compleet = [], 0, True
    for wortelpad, mappen, bestanden in os.walk(pakketmap, followlinks=False):
        mappen[:] = [m for m in mappen if m not in SKIP_DIRS]
        for naam in bestanden:
            if not naam.lower().endswith(PAKKET_TEKST_EXT):
                continue
            if totaal >= PAKKET_LEES_MAX:
                compleet = False
                break
            vol = os.path.join(wortelpad, naam)
            try:
                with open(vol, 'rb') as f:
                    data = f.read(PARTIAL_SCAN_BYTES)
            except OSError:
                continue
            delen.append((os.path.abspath(vol), data))
            totaal += len(data)
        if not compleet:
            break
    _PAKKET_INHOUD[pakketmap] = (delen, compleet)
    return delen, compleet


def wordt_genoemd_in_pakket(pakketmap, bestandspad):
    """
    Noemt enig ander bestand van dit pakket deze bestandsnaam?

    Zo niet, dan kan geen enkel bestand hem includen en breekt er dus niets
    als we hem weghalen. Dat is precies het verschil tussen een echt
    pluginbestand en een achterdeur die alleen via de URL wordt aangeroepen:
    plugins/pro-elements/.../qSAhFi.php staat in de map van Elementor Pro,
    maar hoort er niet bij.

    Bij twijfel geeft deze functie True: dan blijft het bij Review en raken we
    het bestand niet aan. Een gemiste achterdeur is vervelend, een gesloopte
    plugin erger.
    """
    zonder = os.path.splitext(os.path.basename(bestandspad))[0]
    if len(zonder) < 3:
        return True
    delen, compleet = _pakket_inhoud(pakketmap)
    if not compleet:
        return True          # niet alles gelezen, dus niets zeker weten
    naald = zonder.encode('utf-8', 'replace')
    eigen = os.path.abspath(bestandspad)
    for pad, data in delen:
        if pad != eigen and naald in data:
            return True
    return False


def onschuldige_wachter(pad, naam):
    """
    WordPress zet overal een lege index.php ("Silence is golden") of een klein
    403-bestandje. Die willen we niet als bevinding.
    """
    if naam != 'index.php':
        return False
    try:
        if os.path.getsize(pad) > 300:
            return False
    except OSError:
        return False
    t = lees_tekst(pad, 1000)
    if re.search(r'eval|base64|assert|include|require|file_get_contents'
                 r'|shell_exec|passthru|\bexec\s*\(', t, re.I):
        return False

    # Variant 1: helemaal geen dynamische code ("Silence is golden").
    if not re.search(r'\$_(GET|POST|REQUEST|COOKIE|SERVER)', t):
        return True

    # Variant 2: een 403- of 404-afsluiter. Die mag alleen
    # $_SERVER['SERVER_PROTOCOL'] gebruiken, voor de header. Elke andere
    # superglobal in zo'n bestandje hoort er niet.
    if re.search(r'\$_(GET|POST|REQUEST|COOKIE)', t):
        return False
    rest = re.sub(r'\$_SERVER\s*\[\s*[\'"]SERVER_PROTOCOL[\'"]\s*\]', '', t)
    if re.search(r'\$_SERVER', rest):
        return False
    return bool(re.search(r'40[34]|forbidden|not\s+found', t, re.I))


# ---------------------------------------------------------------------------
# Referentiehashes ophalen
# ---------------------------------------------------------------------------

_core_cache = {}


def core_checksums(versie):
    """
    Officiele md5's van de WordPress-core, met de taal waar ze bij horen.
    Geeft (checksums, locale) terug. De locale moet mee: het nl_NL-pakket
    bevat taalbestanden die in het en_US-pakket ontbreken, en als we dan de
    en_US-zip zouden gebruiken om te herstellen, missen precies die bestanden.
    """
    if versie in _core_cache:
        return _core_cache[versie]
    beste, beste_locale = None, 'en_US'
    for locale in ('en_US', 'nl_NL'):
        data = http_json('https://api.wordpress.org/core/checksums/1.0/'
                         '?version=%s&locale=%s' % (versie, locale))
        # De API geeft bij een onbekende versie JSON 'false' terug, geen dict.
        if not isinstance(data, dict):
            continue
        sommen = data.get('checksums')
        if isinstance(sommen, dict) and sommen:
            if beste is None or len(sommen) > len(beste):
                beste, beste_locale = sommen, locale
    _core_cache[versie] = (beste, beste_locale)
    return beste, beste_locale


def plugin_kop(pluginmap):
    """Leest slug en versie uit de hoofd-PHP van een plugin."""
    try:
        bestanden = [b for b in os.listdir(pluginmap) if b.endswith('.php')]
    except OSError:
        return None, None
    for naam in bestanden:
        tekst = lees_tekst(os.path.join(pluginmap, naam), 16000)
        if 'Plugin Name:' not in tekst:
            continue
        m = re.search(r'^[ \t/*#@]*Version:\s*(.+)$', tekst, re.I | re.M)
        versie = m.group(1).strip() if m else None
        if versie:
            versie = re.split(r'\s', versie)[0]
        return os.path.basename(pluginmap.rstrip('/')), versie
    return None, None


def thema_kop(themamap):
    pad = os.path.join(themamap, 'style.css')
    if not os.path.isfile(pad):
        return None, None
    tekst = lees_tekst(pad, 16000)
    m = re.search(r'^[ \t/*#@]*Version:\s*(.+)$', tekst, re.I | re.M)
    versie = m.group(1).strip() if m else None
    if versie:
        versie = re.split(r'\s', versie)[0]
    return os.path.basename(themamap.rstrip('/')), versie


_bestaat_cache = {}


def op_wordpress_org(soort, slug):
    """Staat deze plugin/dit thema op wordpress.org? (premium = nee)"""
    sleutel = (soort, slug)
    if sleutel in _bestaat_cache:
        return _bestaat_cache[sleutel]
    if soort == 'plugin':
        data = http_json('https://api.wordpress.org/plugins/info/1.0/%s.json' % slug)
    else:
        data = http_json('https://api.wordpress.org/themes/info/1.1/'
                         '?action=theme_information&request[slug]=%s' % slug)
    # Bestaat de slug niet, dan komt er JSON 'false' of een {"error": ...}
    # terug. Alleen een dict met een slug erin telt.
    ok = bool(isinstance(data, dict) and not data.get('error')
              and data.get('slug'))
    _bestaat_cache[sleutel] = ok
    return ok


def referentie_hashes(soort, slug, versie):
    """({relpad: md5}, basismap) van het officiele pakket, of (None, None)."""
    if not op_wordpress_org(soort, slug):
        return None, None
    basis = 'https://downloads.wordpress.org/%s/' % soort
    kandidaten = []
    if versie:
        kandidaten.append(('%s%s.%s.zip' % (basis, slug, versie),
                           '%s-%s-%s' % (soort, slug, versie)))
    kandidaten.append(('%s%s.zip' % (basis, slug), '%s-%s-latest' % (soort, slug)))

    for url, sleutel in kandidaten:
        pakket = haal_pakket(url, sleutel)
        if pakket:
            hashes, map_ = pakket_hashes(pakket, slug)
            if hashes:
                return hashes, map_
    return None, None


def oude_kernbestanden(wortel, verwacht):
    """
    De $_old_files-lijst uit de site zelf.

    WordPress houdt in wp-admin/includes/update-core.php precies bij welke
    bestanden bij een update verwijderd moeten worden. Draait de update via
    WordPress zelf, dan gebeurt dat ook. Wordt er alleen overheen gekopieerd
    (handmatig, via een paneel, of na een restore), dan blijven ze staan --
    en dan lijken ze 'niet in het officiele pakket' te horen terwijl het
    gewoon restanten van een oudere versie zijn.

    De lijst wordt alleen gebruikt als update-core.php zelf klopt met het
    officiele pakket. Anders zou een aanvaller er zijn eigen paden in kunnen
    zetten om ze als onschuldig restant te laten wegvallen.

    Geeft (set met paden, set met mapprefixen) terug.
    """
    rel = 'wp-admin/includes/update-core.php'
    vol = os.path.join(wortel, 'wp-admin', 'includes', 'update-core.php')
    if rel not in verwacht or not os.path.isfile(vol):
        return set(), set()
    if hash_bestand(vol) != verwacht[rel]:
        return set(), set()

    tekst = lees_tekst(vol, 600000)
    m = re.search(r'\$_old_files\s*=\s*array\s*\((.*?)\n\s*\)\s*;', tekst, re.S)
    if not m:
        return set(), set()

    bestanden, mappen = set(), set()
    for regel in re.findall(r"'([^'\n]+)'", m.group(1)):
        regel = regel.strip().lstrip('/')
        if not regel:
            continue
        if regel.endswith('/'):
            mappen.add(regel)
        else:
            bestanden.add(regel)
    return bestanden, mappen


def core_bestanden(versie, locale='en_US'):
    """
    Haalt het complete core-zip op in de juiste taal, zodat we besmette
    kernbestanden kunnen terugzetten. De checksums-API geeft alleen hashes,
    geen bestanden.
    """
    kandidaten = []
    if locale and locale != 'en_US':
        taal = locale.split('_')[0]
        kandidaten.append(('https://%s.wordpress.org/wordpress-%s-%s.zip'
                           % (taal, versie, locale),
                           'core-%s-%s' % (versie, locale)))
    kandidaten.append(('https://wordpress.org/wordpress-%s.zip' % versie,
                       'core-%s' % versie))

    for url, sleutel in kandidaten:
        pakket = haal_pakket(url, sleutel)
        if not pakket:
            continue
        basis = os.path.join(pakket, 'wordpress')
        if os.path.isdir(basis):
            return basis
    return None


# ---------------------------------------------------------------------------
# De scan van een installatie
# ---------------------------------------------------------------------------

MALWARE_CATEGORIEEN = (
    'Malware-kenmerken', 'PHP in uploads', 'Verdachte bestandsnaam',
    'Niet in het origineel', 'Op de witte lijst van de aanvaller',
    'PHP in niet-PHP-bestand', 'Aangepaste .htaccess',
)

# Mappen die we nooit als 'lege huls' mogen meenemen, ook niet als ze op dat
# moment toevallig leeg zijn.
NOOIT_OPRUIMEN = {'wp-content', 'wp-admin', 'wp-includes', 'plugins', 'themes',
                  'uploads', 'mu-plugins', 'cgi-bin', '.well-known'}


def consolideer_verdachte_mappen(bevindingen, aanwezig):
    """
    Verdachte mappen waar niets goeds meer in staat gaan in hun geheel weg.

    Drie situaties, en het verschil is belangrijk:
      - alle PHP erin is besmet      -> hele map weg (Critical)
      - helemaal geen bestanden meer -> hele map weg (High). Dit is het geval
        dat lang bleef liggen: een virusscanner haalt de payloads weg en laat
        de mappenstructuur van de aanvaller staan. Er valt dan niets meer te
        vinden, maar de mappen horen er nog steeds niet.
      - er staat ook schone PHP in   -> afblijven, dit blijft mensenwerk

    Daarna lopen we omhoog: een map die verder niets bevat dan zo'n
    veroordeelde map is zelf ook onderdeel van dezelfde structuur.
    """
    besmet = set(b['pad'] for b in bevindingen
                 if b['severity'] in ('Critical', 'High')
                 and b['categorie'] in MALWARE_CATEGORIEEN)

    veroordeeld = {}          # pad -> lijst besmette php-bestanden
    for b in bevindingen:
        if b['categorie'] != 'Verdachte map' or b['actie'] != 'Review':
            continue
        prefix = b['pad'].rstrip('/') + '/'
        onder = [r for r in aanwezig if r.startswith(prefix)]
        php = sorted(r for r in onder if r.lower().endswith(PHP_EXT))
        if any(r not in besmet for r in php):
            continue          # er staat schone PHP in
        if onder and not php:
            continue          # wel bestanden maar geen PHP: te weinig grond
        veroordeeld[b['pad']] = php
        if php:
            b['severity'] = 'Critical'
            b['reden'] = ('Elk PHP-bestand in deze map is besmet, dus de hele '
                          'map kan weg. Wat er verder in staat gaat mee.')
            b['bewijs'] = ['%d besmet PHP-bestand(en):' % len(php)] + php[:8]
        else:
            b['severity'] = 'High'
            b['reden'] = ('Lege map met een onuitspreekbare naam. Hier stond '
                          'iets dat al is weggehaald; de mappenstructuur van '
                          'de aanvaller staat er nog. Er valt niets te '
                          'verliezen door hem weg te halen.')
            b['bewijs'] = ['geen enkel bestand meer in deze map']
        b['actie'] = 'Quarantine'

    if not veroordeeld:
        return bevindingen

    # Omhoog: bevat de map eromheen niets anders meer, dan hoort die er ook
    # niet. Zo blijft er geen lege huls van drie niveaus achter.
    prefixen = set(p.rstrip('/') + '/' for p in veroordeeld)
    extra = []
    for pad in sorted(veroordeeld, key=lambda p: p.count('/'), reverse=True):
        ouder = pad.rsplit('/', 1)[0] if '/' in pad else ''
        while ouder and ouder not in veroordeeld:
            if os.path.basename(ouder) in NOOIT_OPRUIMEN:
                break
            onder = [r for r in aanwezig if r.startswith(ouder + '/')]
            if any(not r.startswith(tuple(prefixen)) for r in onder):
                break
            veroordeeld[ouder] = []
            prefixen.add(ouder + '/')
            extra.append({
                'severity': 'High', 'categorie': 'Verdachte map', 'pad': ouder,
                'reden': 'Bevat niets anders meer dan de verdachte map(pen) '
                         'hierboven; deze huls kan mee weg.',
                'bewijs': [], 'actie': 'Quarantine', 'sha256': None,
                'mtime': None, 'schoon': None, 'herstel': None,
            })
            ouder = ouder.rsplit('/', 1)[0] if '/' in ouder else ''

    # De losse bevindingen eronder hoeven geen eigen regel meer: de map neemt
    # ze mee.
    vast = tuple(prefixen)
    uit = [b for b in bevindingen
           if not (b['pad'] and b['pad'] not in veroordeeld
                   and b['pad'].startswith(vast))]
    return uit + extra


def scan_installatie(inst, offline=False):
    """Scant een WordPress-installatie. Leest alleen; schrijft niets."""
    wortel = inst['root']
    bevindingen = []
    bestandsteller = 0
    totaalgrootte = 0
    hashkaart = {}          # sha256 -> [relpaden]
    slechte_mtimes = []
    gezocht = set()         # achterdeurnamen uit de .htaccess van de aanvaller
    aanwezig = set()        # alles wat we daadwerkelijk op schijf zagen
    kern_ok = kern_mis = 0  # kernbestanden die wel/niet met het pakket kloppen

    def voeg_toe(sev, categorie, rel, reden, bewijs=None, actie='Quarantine',
                 sha=None, mtime=None, schoon=None, herstel=None):
        bevindingen.append({
            'severity': sev, 'categorie': categorie, 'pad': rel,
            'reden': reden, 'bewijs': bewijs or [], 'actie': actie,
            'sha256': sha, 'mtime': mtime,
            # schoon  = pad naar het officiele bestand in de cache
            # herstel = de gerepareerde inhoud, als we die zelf kunnen maken
            'schoon': schoon, 'herstel': herstel,
        })

    # -- 1. Referentiehashes verzamelen -------------------------------------
    geverifieerd = set()    # relpaden die exact overeenkomen met het origineel
    verwacht = {}           # relpad -> officiele md5
    bron = {}               # relpad -> pad naar het schone origineel in de cache

    if not offline and inst.get('versie'):
        sommen, locale = core_checksums(inst['versie'])
        if sommen:
            for rel, md5 in sommen.items():
                verwacht[rel.replace('\\', '/')] = md5
            coremap = core_bestanden(inst['versie'], locale)
            if coremap:
                for rel in sommen:
                    schoon = os.path.join(coremap, *rel.split('/'))
                    if os.path.isfile(schoon):
                        bron[rel.replace('\\', '/')] = schoon
        else:
            voeg_toe('Info', 'Core', '', 'Geen officiele checksums gevonden voor '
                     'WordPress %s' % inst['versie'], actie='Review')

    core_bekend = bool(verwacht)
    # Wat WordPress bij een update had moeten weggooien, maar wat is blijven
    # staan omdat er alleen overheen is gekopieerd.
    oud_bestand, oud_map = ((set(), set()) if not core_bekend
                            else oude_kernbestanden(wortel, verwacht))
    # Andere applicaties naast WordPress. Alleen zoeken waar ze kunnen staan:
    # binnen een WordPress-installatie is elke map al verantwoord.
    andere_apps = (zoek_andere_apps(wortel)
                   if inst.get('soort') == 'los' else [])
    app_prefix = tuple(p + '/' for p, _ in andere_apps if p)
    # Staat de applicatie in de wortel van wat we scannen, dan valt alles
    # eronder; er is dan geen prefix om op te matchen.
    app_wortel = next((n for p, n in andere_apps if not p), None)
    onverifieerbaar = []    # premium plugins/thema's zonder referentie
    verdachte_pakketten = set()  # mappen die zich alleen voordoen als plugin
    # None = niet vastgesteld. Dan blijven alle thema's staan.
    actief = actieve_themas(inst) if inst.get('soort') != 'los' else None
    # Mappen waarvan we het complete officiele pakket kennen. Alles wat daar
    # binnen staat en niet in het pakket voorkomt, is er dus bij gezet.
    volledig_bekend = []

    for soort, submap in (('plugin', 'wp-content/plugins'),
                          ('theme', 'wp-content/themes')):
        basis = os.path.join(wortel, *submap.split('/'))
        if not os.path.isdir(basis):
            continue
        try:
            items = sorted(os.listdir(basis))
        except OSError:
            continue
        for item in items:
            itempad = os.path.join(basis, item)
            if not os.path.isdir(itempad) or os.path.islink(itempad):
                continue

            # Willekeurig ogende mapnaam = vrijwel altijd een gedropte plugin.
            if any(rx.match(item) for rx in RANDOM_DIR_RX):
                voeg_toe('Critical', 'Verdachte map', submap + '/' + item,
                         'Mapnaam ziet eruit als willekeurig gegenereerd '
                         '(typisch voor gedropte malware)')
                continue

            # Ongebruikte standaardthema's zijn geen malware, maar wel code die
            # meedoet aan elke kwetsbaarheid en die niemand bijwerkt. Alleen
            # weghalen als we zeker weten welk thema actief is.
            if (soort == 'theme' and STANDAARDTHEMA_RX.match(item)
                    and actief is not None and item not in actief):
                voeg_toe('Medium', 'Ongebruikt standaardthema',
                         submap + '/' + item,
                         'Standaardthema van WordPress dat niet actief is. '
                         'Ongebruikte thema\'s worden zelden bijgewerkt en '
                         'draaien wel mee in elk lek. Actief is nu: %s.'
                         % ', '.join(sorted(actief)),
                         actie='OudThema')
                continue

            if offline:
                continue

            # De mapnaam is de slug op wordpress.org; de kop geeft de versie.
            if soort == 'plugin':
                _, versie = plugin_kop(itempad)
            else:
                _, versie = thema_kop(itempad)

            hashes, pakketmap = referentie_hashes(soort, item, versie)
            if hashes is None:
                # Wordpress.org kent deze map niet. Bij een gewone naam is dat
                # doodnormaal (premium of maatwerk). Bij een naam als 'ovhvhwl'
                # is het dat niet: dan is dit geen plugin maar een schuilplaats.
                if lijkt_wartaal(item):
                    verdachte_pakketten.add(submap.split('/')[-1] + '/' + item)
                    voeg_toe('Critical', 'Verdachte map', submap + '/' + item,
                             'Onuitspreekbare mapnaam en onbekend op '
                             'wordpress.org. Dit is geen echte plugin/thema '
                             'maar vrijwel zeker gedropte malware.')
                else:
                    onverifieerbaar.append(submap + '/' + item)
                continue
            for rel, md5 in hashes.items():
                sleutel = submap + '/' + item + '/' + rel
                verwacht[sleutel] = md5
                schoon = os.path.join(pakketmap, *rel.split('/'))
                if os.path.isfile(schoon):
                    bron[sleutel] = schoon
            volledig_bekend.append(submap + '/' + item + '/')

    # -- 2. Door de bestanden lopen ----------------------------------------
    overslaan = set(os.path.normpath(p) for p in inst.get('overslaan') or [])
    for wortelpad, mappen, bestanden in os.walk(wortel, followlinks=False):
        mappen[:] = [m for m in mappen
                     if m not in SKIP_DIRS
                     and not os.path.islink(os.path.join(wortelpad, m))
                     and os.path.normpath(
                         os.path.join(wortelpad, m)) not in overslaan]

        # Een map met een onuitspreekbare naam is buiten de pakketmappen net
        # zo verdacht als erin -- maar alleen op plekken waar de naam ook echt
        # iets zegt. In de kern en in uploads zegt hij niets: de kern
        # controleren we met hashes, en in uploads staan nu eenmaal jaartallen
        # en hashmappen van plugins.
        for m in mappen:
            relmap = os.path.relpath(os.path.join(wortelpad, m),
                                     wortel).replace(os.sep, '/')
            if relmap.startswith(GEEN_MAPNAAMCHECK):
                continue
            if VENDOR_RX.search('/' + relmap + '/') or 'cache' in relmap.lower():
                continue
            if PAKKETPAD_RX.match(relmap):
                continue          # daar gaat blok 1 hierboven al over
            if lijkt_wartaal_map(m):
                voeg_toe('High', 'Verdachte map', relmap,
                         'Mapnaam bestaat uit letters zonder klinkers en hoort '
                         'bij geen enkel pakket. Kijk wat erin staat; losse '
                         'bestanden erbinnen worden hieronder apart beoordeeld.',
                         actie='Review')

        for naam in bestanden:
            vol = os.path.join(wortelpad, naam)
            if os.path.islink(vol):
                continue
            rel = os.path.relpath(vol, wortel).replace(os.sep, '/')
            try:
                st = os.lstat(vol)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue

            bestandsteller += 1
            totaalgrootte += st.st_size
            aanwezig.add(rel)
            laag = naam.lower()
            is_php = laag.endswith(PHP_EXT)

            # 2a. Hash vergelijken met het origineel.
            md5, sha = (None, None)
            if rel in verwacht:
                md5, sha = hash_beide(vol)
                is_kern = not rel.startswith('wp-content/')
                if md5 == verwacht[rel]:
                    geverifieerd.add(rel)
                    if is_kern:
                        kern_ok += 1
                    continue
                if is_kern:
                    kern_mis += 1
                # Wijkt af van het origineel: dit is een aangepast kernbestand.
                tekst = lees_tekst(vol)
                treffers = zoek_handtekeningen(tekst)
                is_legit = is_legitiem(rel, laag)
                if treffers:
                    score = max(t['score'] for t in treffers)
                    voeg_toe(sev_van_score(score), 'Aangepast origineel bestand', rel,
                             'Wijkt af van het officiele pakket en bevat '
                             'malware-kenmerken',
                             ['regel %d: %s' % (t['regel'], t['fragment'])
                              for t in treffers[:6]],
                             actie='RestoreOfficial', sha=sha, mtime=st.st_mtime,
                             schoon=bron.get(rel))
                    slechte_mtimes.append(st.st_mtime)
                else:
                    # WordPress genereert de vertaalcaches in wp-content/
                    # languages zelf opnieuw. Dat die afwijken van het pakket
                    # is normaal en zegt niets; wel blijven ze meelopen in de
                    # controle op verstopte PHP hierboven.
                    if (rel.startswith('wp-content/languages/')
                            and not is_php):
                        continue
                    voeg_toe('Medium', 'Aangepast origineel bestand', rel,
                             'Wijkt af van het officiele pakket (geen '
                             'malware-kenmerken gevonden)',
                             actie='RestoreOfficial' if not is_legit else 'Review',
                             sha=sha, mtime=st.st_mtime, schoon=bron.get(rel))
                continue

            # Lege index.php-wachters ("Silence is golden") staan in vrijwel
            # elke uploadmap en zijn nooit een bevinding. Deze controle moet
            # VOOR alle regels hieronder staan, anders wordt elke wachter in
            # wp-content/uploads als kritiek gemeld.
            if onschuldige_wachter(vol, laag):
                continue

            # 2a-bis. Staat het bestand in een map waarvan we het complete
            # officiele pakket kennen, maar zit het niet in dat pakket? Dan is
            # het er door iemand bij gezet. Dit vangt backdoors zonder enige
            # handtekening, zoals wp-includes/wp-conf9x.php.
            in_core = core_bekend and (rel.startswith('wp-admin/')
                                       or rel.startswith('wp-includes/'))
            in_pakket = any(rel.startswith(p) for p in volledig_bekend)
            # .htaccess en .user.ini krijgen verderop hun eigen beoordeling,
            # waar het verschil tussen toegang geven en weigeren wordt
            # gemaakt. Zou je ze hier al afvangen (core levert namelijk geen
            # .htaccess mee, dus ze staan per definitie 'niet in het
            # origineel'), dan mis je precies de aanvallers-.htaccess die php
            # weer uitvoerbaar maakt in een map waar dat geblokkeerd was.
            eigen_beoordeling = naam in ('.htaccess', '.user.ini')

            # 2a-bis-vooraf. Stond dit bestand in een OUDERE WordPress? Dan is
            # het geen gedropt bestand maar een restant van een update die
            # alleen overheen heeft gekopieerd. Denk aan de oude SimplePie- en
            # Requests-mappen: die verhuisden naar src/ en hadden weg gemoeten.
            if in_core and (rel in oud_bestand
                            or any(rel.startswith(d) for d in oud_map)):
                voeg_toe('Low', 'Verouderd kernbestand', rel,
                         'Hoorde bij een oudere WordPress-versie en had bij de '
                         'update verwijderd moeten worden. WordPress laadt het '
                         'niet meer; het staat er alleen nog. Geen malware, wel '
                         'dode code die weg kan.',
                         actie='OudKern', mtime=st.st_mtime)
                continue

            if not eigen_beoordeling and (in_core or (in_pakket and is_php)):
                md5, sha = hash_beide(vol)
                treffers = zoek_handtekeningen(lees_tekst(vol)) if is_php else []
                if in_core and is_php:
                    sev, waar = 'Critical', 'de WordPress-kern'
                elif is_php:
                    sev, waar = 'High', 'een officiele plugin/thema-map'
                else:
                    sev, waar = 'Medium', 'de WordPress-kern'
                voeg_toe(sev, 'Niet in het origineel', rel,
                         'Staat in %s maar komt niet voor in het officiele '
                         'pakket; dit bestand is er bij gezet' % waar,
                         ['regel %d: %s (%s)' % (t['regel'], t['fragment'],
                                                 t['naam'])
                          for t in treffers[:6]],
                         # Een niet-PHP-bestand verplaatsen we niet: dat kan
                         # net zo goed een logo of een taalbestand zijn.
                         actie='Quarantine' if is_php else 'Review',
                         sha=sha, mtime=st.st_mtime)
                if sev in ('Critical', 'High'):
                    slechte_mtimes.append(st.st_mtime)
                if sha:
                    hashkaart.setdefault(sha, []).append(rel)
                continue

            # 2b. PHP in uploads is per definitie fout.
            if is_php and rel.startswith('wp-content/uploads/'):
                md5, sha = hash_beide(vol)
                tekst = lees_tekst(vol)
                treffers = zoek_handtekeningen(tekst)
                voeg_toe('Critical', 'PHP in uploads', rel,
                         'Uitvoerbare PHP in de uploadmap; daar hoort nooit '
                         'PHP te staan',
                         ['regel %d: %s' % (t['regel'], t['fragment'])
                          for t in treffers[:6]], sha=sha, mtime=st.st_mtime)
                slechte_mtimes.append(st.st_mtime)
                if sha:
                    hashkaart.setdefault(sha, []).append(rel)
                continue

            # 2c. Bestandsnaam die vrijwel altijd fout is.
            if BAD_NAME_RX.match(naam):
                md5, sha = hash_beide(vol)
                voeg_toe('Critical', 'Verdachte bestandsnaam', rel,
                         'Bestandsnaam komt overeen met bekende webshells',
                         sha=sha, mtime=st.st_mtime)
                slechte_mtimes.append(st.st_mtime)
                if sha:
                    hashkaart.setdefault(sha, []).append(rel)
                continue

            # 2d. Handtekeningen in de rest.
            # Een awstats- of webalizer-rapport is gegenereerde html die niets
            # uitvoert, en die juist opsomt welke URL's er zijn opgevraagd --
            # inclusief elke scanpoging naar /wso.php. Alleen de php-bestanden
            # in zo'n map zijn interessant.
            if RAPPORT_RX.search('/' + rel) and not is_php:
                continue

            scan_dit = is_php or laag.endswith(TEXTUAL_EXT) or naam in (
                '.htaccess', '.user.ini', 'php.ini')
            if not scan_dit:
                # Goedkope controle: PHP-code verstopt in een 'plaatje'.
                try:
                    with open(vol, 'rb') as f:
                        kop_ = f.read(8192)
                except (IOError, OSError):
                    continue
                if b'<?php' in kop_:
                    md5, sha = hash_beide(vol)
                    voeg_toe('High', 'PHP in niet-PHP-bestand', rel,
                             'Bevat PHP-code terwijl de extensie dat niet '
                             'suggereert', sha=sha, mtime=st.st_mtime)
                    slechte_mtimes.append(st.st_mtime)
                    if sha:
                        hashkaart.setdefault(sha, []).append(rel)
                continue

            tekst = lees_tekst(vol, FULL_SCAN_MAX if st.st_size <= FULL_SCAN_MAX
                               else PARTIAL_SCAN_BYTES)
            alleen_struct = bool(DATA_FILE_RX.match(rel)
                                 or VENDOR_RX.search('/' + rel)
                                 or LOGBESTAND_RX.search('/' + rel))
            is_js = laag.endswith(('.js', '.mjs'))
            treffers = zoek_handtekeningen(tekst, alleen_struct, javascript=is_js)

            # .htaccess: kwaadaardige blokken eruit, de rest laten staan.
            if naam == '.htaccess':
                schoon, weg, witte_lijst = repareer_htaccess(tekst)
                gezocht |= witte_lijst
                if weg:
                    slechte_mtimes.append(st.st_mtime)
                    # WordPress levert zelf geen .htaccess in wp-admin of
                    # wp-includes. Staat daar toch een aanvallersblok in, dan
                    # is het hele bestand er bij gezet en moet het er ook
                    # helemaal uit. Repareren zou het deny-blok laten staan,
                    # en dat blokkeert alle PHP in die map: in wp-admin legt
                    # dat je hele beheeromgeving plat.
                    in_kern = (rel.startswith('wp-admin/')
                               or rel.startswith('wp-includes/'))
                    if not schoon or in_kern:
                        voeg_toe('High', 'Aangepaste .htaccess', rel,
                                 ('WordPress levert hier zelf geen .htaccess; '
                                  'dit bestand is er in zijn geheel bij gezet'
                                  if in_kern else
                                  'Bevat uitsluitend een aanvallersblok; het '
                                  'hele bestand kan weg'),
                                 weg[:6], actie='Quarantine',
                                 mtime=st.st_mtime)
                    else:
                        voeg_toe('High', 'Aangepaste .htaccess', rel,
                                 'Bevat een aanvallersblok tussen legitieme '
                                 'regels; alleen die regels moeten eruit',
                                 weg[:6], actie='FixInPlace',
                                 mtime=st.st_mtime, herstel=schoon + '\n')
                    continue

            if not treffers:
                # PHP zonder handtekening dat we niet tegen een origineel
                # konden leggen: hash bewaren voor de vergelijking tussen
                # sites. Daar komt de malware uit die geen enkele
                # handtekening raakt.
                if is_php:
                    md5, sha = hash_beide(vol)
                    if sha:
                        hashkaart.setdefault(sha, []).append(rel)
                continue

            score = max(t['score'] for t in treffers)
            sev = sev_van_score(score)
            if VENDOR_RX.search('/' + rel) and sev == 'Critical':
                sev = 'High'
            # Een .txt draait niet. Alleen als de handtekening op verhulling
            # wijst blijft de ernst staan; een losse create_function() in een
            # tekstbestand is een restant van de bouwer.
            if (sev in ('Critical', 'High') and not is_php
                    and laag.endswith(NIET_UITVOERBAAR)
                    and not any(t['naam'] in STRUCTURAL for t in treffers)):
                sev = 'Medium'

            md5, sha = hash_beide(vol)
            if sha:
                hashkaart.setdefault(sha, []).append(rel)

            is_legit = is_legitiem(rel, laag)
            pakket = hoort_bij_pakket(rel, verdachte_pakketten)
            herstel_php = None
            if is_legit:
                # Dit bestand moet blijven staan, dus proberen we de injectie
                # eruit te knippen. Drie voorwaarden voordat we dat aanbieden:
                # het bestand moet volledig en als geldige UTF-8 te lezen zijn,
                # de reparatie moet echt iets weghalen zonder dat er
                # handtekeningen overblijven, en er mag niet meer dan de helft
                # van het bestand verdwijnen. Daarna controleert het shell-
                # script ook nog de PHP-syntax met php -l.
                exact = (lees_tekst_exact(vol)
                         if st.st_size <= FULL_SCAN_MAX else None)
                if exact:
                    kandidaat, weg_php = repareer_php(exact)
                    # De ondergrens vangt het geval waarin de reparatie het
                    # bestand leegtrekt: php -l vindt een leeg bestand namelijk
                    # prima, dus daar redt die controle je niet.
                    if (weg_php
                            and len(kandidaat) >= max(60, len(exact) * 0.3)
                            and not zoek_handtekeningen(kandidaat)):
                        herstel_php = kandidaat

                if herstel_php is not None:
                    actie = 'FixInPlace'
                    reden = ('Ingeplakte code in een bestand dat moet blijven '
                             'staan. Alleen die code wordt verwijderd, de rest '
                             'van het bestand blijft ongemoeid.')
                else:
                    actie = 'Review'
                    reden = ('Malware-kenmerken in een bestand dat bij het '
                             'thema/de plugin hoort. Weggooien breekt de site, '
                             'en de injectie is niet automatisch te isoleren. '
                             'Kijk hier zelf naar.')
            elif pakket:
                # Standaard blijft dit mensenwerk: zomaar een bestand uit een
                # plugin trekken sloopt die plugin.
                actie = 'Review'
                pakketmap = os.path.join(wortel, 'wp-content',
                                         *pakket.split('/'))
                # Bestanden in de hoofdmap van een pakket laat ik met rust.
                # Het hoofdbestand van een plugin en uninstall.php worden door
                # WordPress zelf geladen, niet door een ander pluginbestand;
                # die zouden dus altijd 'nergens genoemd' zijn en het weghalen
                # ervan schakelt de hele plugin uit.
                binnen = rel[len('wp-content/' + pakket + '/'):]
                # Alleen bij Critical de moeite nemen om na te gaan of het
                # bestand er echt bij hoort. Vendor-mappen komen hier nooit
                # binnen: die zijn hierboven al naar High teruggezet.
                if (sev == 'Critical' and '/' in binnen
                        and not wordt_genoemd_in_pakket(pakketmap, vol)):
                    actie = 'Quarantine'
                    reden = ('Malware-kenmerken, en geen enkel ander bestand '
                             'van %s noemt deze bestandsnaam. Dit hoort dus '
                             'niet bij het pakket maar is er alleen in '
                             'neergezet; weghalen breekt niets.' % pakket)
                else:
                    reden = ('Malware-kenmerken in een bestand van %s. Niet '
                             'verplaatsen: dan werkt dat pakket niet meer. '
                             'Klopt het echt, herinstalleer dan de hele '
                             'plugin/het thema.' % pakket)
            elif app_wortel or rel.startswith(app_prefix):
                # Een andere webapplicatie. Precies dezelfde afweging als bij
                # een plugin: er zomaar een bestand uit trekken sloopt hem, en
                # legitieme Joomla- of Drupal-code gebruikt nu eenmaal
                # shell_exec() en backticks.
                app = next((n for p, n in andere_apps
                            if p and rel.startswith(p + '/')), app_wortel
                           or 'een applicatie')
                actie = 'Review'
                reden = ('Malware-kenmerken in een bestand van %s. Niet '
                         'verplaatsen: dan werkt die installatie niet meer. '
                         'Klopt het echt, herinstalleer dan het pakket.' % app)
            else:
                actie = 'Quarantine'
                reden = 'Malware-kenmerken gevonden'

            voeg_toe(sev, 'Malware-kenmerken', rel, reden,
                     ['regel %d: %s (%s)' % (t['regel'], t['fragment'], t['naam'])
                      for t in treffers[:6]],
                     actie=actie, sha=sha, mtime=st.st_mtime,
                     herstel=herstel_php)
            if sev in ('Critical', 'High'):
                slechte_mtimes.append(st.st_mtime)

    # -- 2a-ter. Klopt de gemelde versie wel? --------------------------------
    # Wijkt een groot deel van de kern af, dan is de kans veel groter dat
    # version.php niet klopt dan dat iemand honderden bestanden heeft
    # aangepast. Dat gebeurt bij een half mislukte update, en een aanvaller
    # kan het ook bewust doen om de vergelijking waardeloos te maken. Zonder
    # deze controle verzuipt het rapport in nietszeggende meldingen.
    kern_totaal = kern_ok + kern_mis
    if kern_totaal >= 50 and kern_mis > kern_totaal * 0.3:
        voeg_toe('High', 'Versie klopt niet', 'wp-includes/version.php',
                 '%d van de %d kernbestanden wijken af van WordPress %s. Zo '
                 'veel verschil betekent bijna altijd dat de gemelde versie '
                 'niet klopt, niet dat alles besmet is. Controleer '
                 'version.php en werk WordPress opnieuw bij; scan daarna '
                 'opnieuw.' % (kern_mis, kern_totaal, inst.get('versie')),
                 actie='Review')

    # -- 2b. Wat ONTBREEKT ---------------------------------------------------
    # Een besmet kernbestand dat door een virusscanner is weggehaald in plaats
    # van schoongemaakt, legt de site plat. Zonder index.php in de webroot
    # herschrijft .htaccess naar een bestand dat niet bestaat en krijgt de
    # bezoeker een 404, terwijl /wp-admin/ gewoon blijft werken.
    if verwacht:
        for rel in KERNBESTANDEN:
            if rel in aanwezig or rel not in verwacht:
                continue
            voeg_toe('Critical', 'Kernbestand ontbreekt', rel,
                     'Dit bestand hoort bij WordPress maar staat er niet meer. '
                     'Zonder dit bestand werkt (een deel van) de site niet.',
                     actie='RestoreOfficial', schoon=bron.get(rel))

        # De rest van de kern, samengevat: losse ontbrekende bestanden zijn
        # zelden urgent, maar tientallen tegelijk zeggen wel iets.
        overig = [r for r in verwacht
                  if r.endswith('.php') and r not in aanwezig
                  and r not in KERNBESTANDEN
                  and (r.startswith('wp-admin/') or r.startswith('wp-includes/'))]
        if overig:
            voeg_toe('Medium', 'Kernbestand ontbreekt', '',
                     '%d bestand(en) uit het officiele pakket ontbreken. Dat '
                     'wijst op een halve update of een te ruwe opschoning.'
                     % len(overig), sorted(overig)[:20], actie='Review')

    # -- 3. Tweede ronde: de golf en de witte lijst --------------------------
    # Alles wat binnen vijf minuten van een bevestigde treffer is aangeraakt
    # hoort waarschijnlijk bij dezelfde inbraak, ook zonder handtekening. En
    # als de aanvaller in een .htaccess bestandsnamen op de witte lijst heeft
    # gezet, zoeken we die namen door de hele installatie.
    if slechte_mtimes or gezocht:
        gemeld = set(b['pad'] for b in bevindingen)
        vensters = sorted(set(int(m // 300) for m in slechte_mtimes))
        extra = 0
        for wortelpad, mappen, bestanden in os.walk(wortel, followlinks=False):
            # Dezelfde uitsluiting als in de eerste ronde. Zonder deze regel
            # liep de scan van de domeinmap alsnog de WordPress-installatie in
            # die daar juist buiten valt -- en daar hebben we op dat niveau
            # geen enkele referentie voor, dus dan lijkt de hele kern verdacht.
            mappen[:] = [m for m in mappen
                         if m not in SKIP_DIRS
                         and not os.path.islink(os.path.join(wortelpad, m))
                         and os.path.normpath(
                             os.path.join(wortelpad, m)) not in overslaan]
            for naam in bestanden:
                if not naam.lower().endswith(PHP_EXT):
                    continue
                vol = os.path.join(wortelpad, naam)
                if os.path.islink(vol):
                    continue
                rel = os.path.relpath(vol, wortel).replace(os.sep, '/')
                if rel in gemeld or rel in geverifieerd:
                    continue
                try:
                    mt = os.lstat(vol).st_mtime
                except OSError:
                    continue

                # Staat deze naam op de witte lijst van de aanvaller? Dan is
                # het zijn achterdeur. 'rel not in verwacht' houdt de echte
                # wp-login.php in de webroot buiten schot: die staat op zijn
                # eigen plek in het officiele pakket.
                # De naamcontrole staat er dubbel op. gewhitelist_namen() haalt
                # WordPress-namen er al uit, maar dit is het punt waarop een
                # fout de kern van de site naar quarantaine stuurt. Dat risico
                # is een tweede regel waard.
                if (naam in gezocht and rel not in verwacht
                        and naam.lower() not in WP_KERNNAMEN):
                    _m, sha = hash_beide(vol)
                    voeg_toe('Critical', 'Op de witte lijst van de aanvaller',
                             rel,
                             'Deze naam staat in een .htaccess van de aanvaller '
                             'op de witte lijst. Dat doet hij alleen voor zijn '
                             'eigen achterdeur.',
                             ['gewijzigd: ' + time.strftime(
                                 '%Y-%m-%d %H:%M:%S', time.localtime(mt))],
                             sha=sha, mtime=mt)
                    if sha:
                        hashkaart.setdefault(sha, []).append(rel)
                    continue

                if vensters and int(mt // 300) in vensters:
                    voeg_toe('Medium', 'Zelfde tijdstip als de inbraak', rel,
                             'Aangepast in hetzelfde tijdvenster als de '
                             'bevestigde besmette bestanden',
                             ['gewijzigd: ' + time.strftime(
                                 '%Y-%m-%d %H:%M:%S', time.localtime(mt))],
                             actie='Review', mtime=mt)
                    extra += 1
                    if extra >= 200:
                        break
            if extra >= 200:
                break
        if extra >= 200:
            voeg_toe('Info', 'Zelfde tijdstip als de inbraak', '',
                     'Er zijn meer dan 200 bestanden uit hetzelfde tijdvenster; '
                     'de lijst is afgekapt. Bij zoveel treffers is de hele '
                     'installatie verdacht en is opnieuw opbouwen sneller.',
                     actie='Review')

    if gezocht:
        voeg_toe('Info', 'Witte lijst van de aanvaller', '',
                 'In de .htaccess-bestanden van de aanvaller staan deze namen '
                 'op de witte lijst. Zoek ze ook op je andere sites: het is '
                 'zijn eigen lijst achterdeuren.',
                 sorted(gezocht), actie='Review')

    for pad, app in andere_apps:
        voeg_toe('Info', 'Andere applicatie', pad or '(deze map)',
                 'Hier staat een %s. Die vergelijken we met niets, dus '
                 'bestanden erbinnen worden nooit automatisch verplaatst. '
                 'Draait hij nog en is hij bij? Zo niet, dan is dit een lek '
                 'dat losstaat van WordPress.' % app, actie='Review')

    for pad in onverifieerbaar:
        voeg_toe('Info', 'Niet te verifieren', pad,
                 'Staat niet op wordpress.org (premium of maatwerk); kan niet '
                 'met een origineel vergeleken worden',
                 actie='Review')

    # -- 4. Aanvallersmappen in hun geheel ----------------------------------
    bevindingen = consolideer_verdachte_mappen(bevindingen, aanwezig)

    # De pakketinhoud die we voor deze site inlazen is verder nutteloos.
    _PAKKET_INHOUD.clear()

    inst['bevindingen'] = bevindingen
    inst['bestanden'] = bestandsteller
    inst['grootte'] = totaalgrootte
    inst['hashkaart'] = hashkaart
    inst['geverifieerd'] = len(geverifieerd)
    return inst


# ---------------------------------------------------------------------------
# Controles die alleen als root kunnen
# ---------------------------------------------------------------------------

def scan_user_extras(user):
    """Cron, SSH-sleutels, php-ini's en rechten. Dit kan de lokale tool niet."""
    bevindingen = []

    def voeg_toe(sev, categorie, pad, reden, bewijs=None):
        bevindingen.append({'severity': sev, 'categorie': categorie,
                            'pad': pad, 'reden': reden, 'bewijs': bewijs or [],
                            'actie': 'Review', 'sha256': None, 'mtime': None})

    # Crontab. Dit is de meest gemiste vorm van persistentie.
    for cronpad in ('/var/spool/cron/%s' % user,
                    '/var/spool/cron/crontabs/%s' % user):
        if not os.path.isfile(cronpad):
            continue
        try:
            with open(cronpad, 'r', errors='replace') as f:
                regels = f.read().splitlines()
        except (IOError, OSError):
            continue
        for nr, regel in enumerate(regels, 1):
            if not regel.strip() or regel.lstrip().startswith('#'):
                continue
            if CRON_BAD_RX.search(regel):
                voeg_toe('Critical', 'Crontab', cronpad,
                         'Verdachte cronregel: haalt code op of voert iets uit '
                         '/tmp uit', ['regel %d: %s' % (nr, regel.strip()[:160])])

    # SSH-sleutels.
    sleutelpad = os.path.join(HOME_DIR, user, '.ssh', 'authorized_keys')
    if os.path.isfile(sleutelpad):
        try:
            with open(sleutelpad, 'r', errors='replace') as f:
                sleutels = [r for r in f.read().splitlines()
                            if r.strip() and not r.startswith('#')]
        except (IOError, OSError):
            sleutels = []
        if sleutels:
            # Bewust Medium: veel users hebben legitiem een sleutel. Het gaat
            # erom dat je ze een keer met eigen ogen naloopt.
            voeg_toe('Medium', 'SSH-sleutels', sleutelpad,
                     '%d SSH-sleutel(s) aanwezig. Controleer of je die '
                     'allemaal herkent.' % len(sleutels),
                     [s[-70:] for s in sleutels[:5]])

    # PHP buiten elke webmap. De domeinmappen zelf worden nu meegescand, maar
    # /home/<user>/ en /home/<user>/domains/ horen bij geen enkele site en
    # blijven anders buiten beeld. Alleen het eerste niveau: dieper zit al
    # dekking.
    for map_ in (os.path.join(HOME_DIR, user),
                 os.path.join(HOME_DIR, user, 'domains')):
        try:
            namen = sorted(os.listdir(map_))
        except OSError:
            continue
        for naam in namen:
            vol = os.path.join(map_, naam)
            if not naam.lower().endswith(PHP_EXT):
                continue
            if os.path.islink(vol) or not os.path.isfile(vol):
                continue
            treffers = zoek_handtekeningen(lees_tekst(vol))
            voeg_toe('High' if treffers else 'Medium', 'PHP buiten de webmap',
                     vol,
                     'Een PHP-bestand op een plek waar geen website staat. '
                     'Daar hoort niets uitvoerbaars, en het is een bekende '
                     'schuilplaats voor een tweede achterdeur.',
                     ['regel %d: %s (%s)' % (t['regel'], t['fragment'],
                                             t['naam'])
                      for t in treffers[:4]])

    # php.ini / .user.ini met auto_prepend_file, en wereldschrijfbare mappen.
    schrijfbaar = []
    basis = os.path.join(HOME_DIR, user, 'domains')
    if os.path.isdir(basis):
        for wortelpad, mappen, bestanden in os.walk(basis, followlinks=False):
            mappen[:] = [m for m in mappen
                         if m not in SKIP_DIRS and m != 'private_html'
                         and not os.path.islink(os.path.join(wortelpad, m))]
            for naam in bestanden:
                if naam not in ('.user.ini', 'php.ini'):
                    continue
                vol = os.path.join(wortelpad, naam)
                tekst = lees_tekst(vol, 40000)
                if re.search(r'auto_(prepend|append)_file\s*=\s*\S', tekst):
                    m = re.search(r'^.*auto_(prepend|append)_file.*$',
                                  tekst, re.M)
                    voeg_toe('Critical', 'PHP-configuratie', vol,
                             'auto_prepend/append_file laadt bij elke '
                             'aanvraag een extra bestand',
                             [m.group(0).strip()[:160]] if m else [])
            for mapnaam in mappen:
                vol = os.path.join(wortelpad, mapnaam)
                try:
                    modus = os.lstat(vol).st_mode
                except OSError:
                    continue
                if modus & stat.S_IWOTH:
                    schrijfbaar.append('%s (%o)' % (vol, modus & 0o777))

    # Gebundeld: op een hostingserver zijn dit er zo tientallen, en dan drukken
    # ze de echte vondsten uit het rapport.
    if schrijfbaar:
        voeg_toe('Medium', 'Rechten', os.path.join(HOME_DIR, user),
                 '%d map(pen) zijn voor iedereen schrijfbaar (777). Dat is hoe '
                 'een lek op de ene site de buren kan besmetten.'
                 % len(schrijfbaar), schrijfbaar[:25])

    return bevindingen


def scan_server_breed():
    """Eenmalige servercontroles."""
    bevindingen = []

    def voeg_toe(sev, categorie, pad, reden, bewijs=None):
        bevindingen.append({'severity': sev, 'categorie': categorie,
                            'pad': pad, 'reden': reden, 'bewijs': bewijs or [],
                            'actie': 'Review', 'sha256': None, 'mtime': None})

    if os.path.isfile('/etc/ld.so.preload'):
        inhoud = lees_tekst('/etc/ld.so.preload', 4000).strip()
        if inhoud:
            voeg_toe('Critical', 'Server', '/etc/ld.so.preload',
                     'Bestaat en is niet leeg. Dit is een klassieke rootkit-plek.',
                     [inhoud[:200]])

    # Processen die als een website-user draaien maar geen webserver zijn.
    try:
        uit = subprocess.check_output(['ps', '-eo', 'user:32,pid,etimes,args'],
                                      stderr=subprocess.DEVNULL)
        # De (?<![\w/]) is nodig omdat maldet zijn eigen werkmap
        # /usr/local/maldetect/tmp/.find.NNN noemt: zonder die grens leest de
        # regel dat als een verborgen bestand in /tmp.
        verdacht_rx = re.compile(
            r'(curl|wget)\s+[^|]*\|\s*(ba)?sh'
            r'|(?<![\w/])/tmp/\.|(?<![\w/])/dev/shm/'
            r'|xmrig|minerd|kdevtmpfsi|kinsing', re.I)
        # Scanners rommelen per definitie in verdachte paden. Die zijn niet
        # het probleem, die zoeken het probleem.
        eigen_rx = re.compile(
            r'/(clamd?scan|clamd|freshclam|maldet|rkhunter|chkrootkit)\b'
            r'|/usr/local/maldetect/|imunify', re.I)
        for regel in uit.decode('utf-8', 'replace').splitlines()[1:]:
            if verdacht_rx.search(regel) and not eigen_rx.search(regel):
                voeg_toe('Critical', 'Server', 'proces',
                         'Verdacht draaiend proces', [regel.strip()[:200]])
    except Exception:
        pass

    return bevindingen


# ---------------------------------------------------------------------------
# Onderlinge vergelijking tussen sites
# ---------------------------------------------------------------------------

def vergelijk_sites(alle_installaties):
    """
    Het voordeel van dertig sites tegelijk: dezelfde malware staat op meerdere
    sites. Een hash die op veel sites voorkomt en nergens in een officieel
    pakket zit, is malware - ook zonder handtekening. En een hash die al ergens
    bevestigd besmet is, is dat overal.
    """
    extra = defaultdict(list)

    # 1. Hashes die al ergens als besmet zijn aangemerkt. Alleen bevindingen
    #    die we zelf naar quarantaine durven te sturen tellen mee. Een 'Review'
    #    is per definitie twijfel, en die twijfel mag niet op de andere sites
    #    ineens als zekerheid terugkomen -- juist gedeelde premium plugins
    #    staan op elke site met exact dezelfde hash.
    bekend_slecht = {}
    for inst in alle_installaties:
        for b in inst.get('bevindingen', []):
            if (b['sha256'] and b['severity'] in ('Critical', 'High')
                    and b['actie'] == 'Quarantine'):
                bekend_slecht[b['sha256']] = b['reden']

    # 2. Hoe vaak komt elke hash voor, over alle sites?
    voorkomens = defaultdict(list)
    for inst in alle_installaties:
        sleutel = '%s/%s' % (inst['user'], inst['domein'])
        for sha, paden in inst.get('hashkaart', {}).items():
            for pad in paden:
                voorkomens[sha].append((sleutel, inst, pad))

    for sha, plekken in voorkomens.items():
        sites = set(p[0] for p in plekken)

        if sha in bekend_slecht:
            for sleutel, inst, pad in plekken:
                al = any(b['pad'] == pad and b['sha256'] == sha
                         for b in inst['bevindingen'])
                if al:
                    continue
                extra[id(inst)].append({
                    'severity': 'Critical', 'categorie': 'Zelfde bestand als op andere site',
                    'pad': pad,
                    'reden': 'Identiek (sha256) aan een bestand dat op een '
                             'andere site als besmet is aangemerkt',
                    'bewijs': ['staat op %d site(s)' % len(sites),
                               'sha256: ' + sha[:16]],
                    'actie': 'Quarantine', 'sha256': sha, 'mtime': None,
                })
            continue

        if len(sites) < 3:
            continue

        # Een gedeelde premium-plugin staat op tien sites op exact hetzelfde
        # pad. Dat is normaal en mag hier niet uit komen, anders verzuipt het
        # rapport. Malware valt juist op doordat het op wisselende paden staat,
        # of buiten de plugin- en themamappen.
        paden = set(p[2] for p in plekken)
        if any(VENDOR_RX.search('/' + p) for p in paden):
            continue
        in_pakketmap = all(
            re.match(r'wp-content/(plugins|themes)/[^/]+/', p) for p in paden)
        if in_pakketmap and len(paden) == 1:
            continue

        for sleutel, inst, pad in plekken:
            if any(b['pad'] == pad for b in inst['bevindingen']):
                continue
            if sum(1 for b in extra[id(inst)]
                   if b['categorie'] == 'Zelfde bestand als op andere site') >= 25:
                continue
            extra[id(inst)].append({
                'severity': 'Medium',
                'categorie': 'Zelfde bestand als op andere site',
                'pad': pad,
                'reden': 'Ditzelfde bestand (sha256) staat op %d sites, op %d '
                         'verschillende plek(ken), en komt in geen enkel '
                         'officieel pakket voor' % (len(sites), len(paden)),
                'bewijs': sorted(sites)[:8] + ['sha256: ' + sha[:16]],
                'actie': 'Review', 'sha256': sha, 'mtime': None,
            })

    for inst in alle_installaties:
        if id(inst) in extra:
            inst['bevindingen'].extend(extra[id(inst)])
    return alle_installaties


# ---------------------------------------------------------------------------
# Rapportage
# ---------------------------------------------------------------------------

SEV_VOLGORDE = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}


def tel_severity(bevindingen):
    tellers = defaultdict(int)
    for b in bevindingen:
        tellers[b['severity']] += 1
    return tellers


def schrijf_html(uitmap, installaties, server_bev, gescande_users, duur):
    pad = os.path.join(uitmap, 'rapport.html')
    kleuren = {'Critical': '#c0392b', 'High': '#e67e22', 'Medium': '#2980b9',
               'Low': '#7f8c8d', 'Info': '#95a5a6'}

    alle = []
    for inst in installaties:
        alle.extend(inst.get('bevindingen', []))
    alle.extend(server_bev)
    tot = tel_severity(alle)

    def esc(s):
        return (str(s).replace('&', '&amp;').replace('<', '&lt;')
                .replace('>', '&gt;'))

    uit = io.StringIO()
    uit.write("""<!doctype html><html lang="nl"><head><meta charset="utf-8">
<title>WordPress-vlootscan</title><style>
body{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;
 background:#f5f6f7;color:#222}
.wrap{max-width:1150px;margin:0 auto;padding:24px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 8px}
.meta{color:#666;font-size:13px;margin-bottom:20px}
.kaarten{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0 24px}
.kaart{background:#fff;border-radius:6px;padding:12px 16px;min-width:96px;
 box-shadow:0 1px 3px rgba(0,0,0,.09)}
.kaart b{display:block;font-size:24px;line-height:1.1}
.kaart span{font-size:12px;color:#666}
.site{background:#fff;border-radius:6px;margin-bottom:16px;
 box-shadow:0 1px 3px rgba(0,0,0,.09);overflow:hidden}
.sitekop{padding:12px 16px;border-bottom:1px solid #eee;display:flex;
 justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}
.sitekop b{font-size:15px}.sitekop .sub{color:#777;font-size:12px}
table{width:100%;border-collapse:collapse}
td,th{padding:7px 16px;border-bottom:1px solid #f0f0f0;
 vertical-align:top;text-align:left}
th{font-size:11px;text-transform:uppercase;color:#888;letter-spacing:.5px}
.sev{display:inline-block;padding:1px 7px;border-radius:3px;color:#fff;
 font-size:11px;font-weight:600}
code{font-family:Menlo,Consolas,monospace;font-size:12px;
 background:#f4f4f4;padding:1px 4px;border-radius:3px;word-break:break-all}
.bewijs{color:#666;font-size:12px;margin-top:3px;
 font-family:Menlo,Consolas,monospace;word-break:break-all}
.leeg{padding:16px;color:#27ae60}
</style></head><body><div class="wrap">""")

    uit.write('<h1>WordPress-vlootscan</h1><div class="meta">%s &middot; '
              '%d user(s) gescand &middot; %d installatie(s) &middot; '
              'scanduur %d min</div>'
              % (time.strftime('%d-%m-%Y %H:%M'), gescande_users,
                 len(installaties), duur // 60))

    uit.write('<div class="kaarten">')
    for sev in ('Critical', 'High', 'Medium', 'Low', 'Info'):
        uit.write('<div class="kaart"><b style="color:%s">%d</b>'
                  '<span>%s</span></div>' % (kleuren[sev], tot.get(sev, 0), sev))
    uit.write('</div>')

    if server_bev:
        uit.write('<h2>Server</h2><div class="site"><table>'
                  '<tr><th>Ernst</th><th>Wat</th></tr>')
        for b in sorted(server_bev, key=lambda x: SEV_VOLGORDE[x['severity']]):
            uit.write('<tr><td><span class="sev" style="background:%s">%s</span>'
                      '</td><td><code>%s</code><br>%s%s</td></tr>'
                      % (kleuren[b['severity']], b['severity'], esc(b['pad']),
                         esc(b['reden']),
                         ''.join('<div class="bewijs">%s</div>' % esc(e)
                                 for e in b['bewijs'])))
        uit.write('</table></div>')

    volgorde = sorted(installaties, key=lambda i: (
        -sum(1 for b in i.get('bevindingen', [])
             if b['severity'] in ('Critical', 'High')),
        i['user'], i['domein']))

    for inst in volgorde:
        bev = sorted(inst.get('bevindingen', []),
                     key=lambda x: (SEV_VOLGORDE[x['severity']], x['pad']))
        t = tel_severity(bev)
        soort = ('WP %s' % (inst.get('versie') or '?')
                 if inst.get('soort') != 'los' else 'geen WordPress')
        uit.write('<div class="site"><div class="sitekop"><div><b>%s</b>'
                  '<div class="sub">user %s &middot; %s &middot; %s '
                  'bestanden &middot; %d geverifieerd tegen origineel</div>'
                  '</div><div>' % (esc(inst_naam(inst)),
                                   esc(inst['user']), esc(soort),
                                   inst.get('bestanden', 0),
                                   inst.get('geverifieerd', 0)))
        for sev in ('Critical', 'High', 'Medium'):
            if t.get(sev):
                uit.write('<span class="sev" style="background:%s">%d %s</span> '
                          % (kleuren[sev], t[sev], sev))
        uit.write('</div></div>')

        if not bev:
            uit.write('<div class="leeg">Geen bevindingen.</div></div>')
            continue

        uit.write('<table><tr><th>Ernst</th><th>Bestand</th><th>Reden</th>'
                  '<th>Voorstel</th></tr>')
        for b in bev:
            # Bij het voorstel meteen of opruimen.sh het ook echt oppakt. Dat
            # scheelt het naast elkaar leggen van rapport en script.
            voorstel = esc(b['actie'])
            if b['severity'] in ('Critical', 'High'):
                if b.get('gedaan'):
                    voorstel += ('<div class="bewijs" style="color:#27ae60">'
                                 'staat in opruimen.sh</div>')
                else:
                    voorstel += ('<div class="bewijs" style="color:#c0392b">'
                                 'zelf doen: %s</div>' % esc(waarom_lang(b)))
            uit.write('<tr><td><span class="sev" style="background:%s">%s</span>'
                      '</td><td><code>%s</code></td><td>%s%s</td><td>%s</td></tr>'
                      % (kleuren[b['severity']], b['severity'], esc(b['pad']),
                         esc(b['reden']),
                         ''.join('<div class="bewijs">%s</div>' % esc(e)
                                 for e in b['bewijs']),
                         voorstel))
        uit.write('</table></div>')

    uit.write('</div></body></html>')
    with open(pad, 'w', encoding='utf-8') as f:
        f.write(uit.getvalue())
    return pad


def schrijf_json(uitmap, installaties, server_bev):
    pad = os.path.join(uitmap, 'bevindingen.json')

    def kaal(b):
        # De gerepareerde inhoud staat al als bestand in reparaties/; die hoeft
        # niet ook nog een keer in de JSON, dat maakt het bestand onleesbaar.
        return dict((k, v) for k, v in b.items() if k != 'herstel')

    data = {
        'tijdstip': time.strftime('%Y-%m-%d %H:%M:%S'),
        'server': server_bev,
        'installaties': [{
            'user': i['user'], 'domein': i['domein'], 'root': i['root'],
            'submap': i['submap'], 'versie': i.get('versie'),
            'bestanden': i.get('bestanden', 0),
            'geverifieerd': i.get('geverifieerd', 0),
            'bevindingen': [kaal(b) for b in i.get('bevindingen', [])],
        } for i in installaties],
    }
    with open(pad, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=1, ensure_ascii=False)
    return pad


SH_HULP = '''
PHPBIN="$(command -v php 2>/dev/null || echo '')"
MYSQLBIN="$(command -v mariadb 2>/dev/null || command -v mysql 2>/dev/null || echo '')"
verplaatst=0; hersteld=0; gerepareerd=0; accounts=0; mislukt=0

# Verplaatst een besmet bestand naar de quarantainemap.
mv_safe() {
  if [ ! -e "$1" ]; then echo "  bestaat niet (al opgeruimd?): $1"; return; fi
  mkdir -p "$(dirname "$2")"
  if mv "$1" "$2"; then verplaatst=$((verplaatst+1))
  else echo "  MISLUKT: $1"; mislukt=$((mislukt+1)); fi
}

# Zet het officiele bestand terug. $1=schoon origineel $2=live $3=backup
# cp op een bestaand bestand behoudt eigenaar en rechten van dat bestand.
herstel_safe() {
  if [ ! -f "$1" ]; then echo "  niet in cache: $1"; mislukt=$((mislukt+1)); return; fi

  # Het bestand ontbreekt helemaal: neerzetten en de eigenaar overnemen van de
  # map eromheen. Zonder die chown komt het op root te staan en kan de site er
  # niet meer bij.
  if [ ! -e "$2" ]; then
    mkdir -p "$(dirname "$2")"
    if cp "$1" "$2"; then
      chown "$(stat -c '%u:%g' "$(dirname "$2")")" "$2" 2>/dev/null
      chmod 644 "$2"
      hersteld=$((hersteld+1)); echo "  ontbrak, teruggeplaatst: $2"
    else echo "  MISLUKT: $2"; mislukt=$((mislukt+1)); fi
    return
  fi

  mkdir -p "$(dirname "$3")"
  if ! cp -p "$2" "$3"; then echo "  BACKUP MISLUKT, overgeslagen: $2"; mislukt=$((mislukt+1)); return; fi
  if cp "$1" "$2"; then hersteld=$((hersteld+1))
  else echo "  MISLUKT: $2"; mislukt=$((mislukt+1)); fi
}

# Zet de gerepareerde versie terug. $1=reparatie $2=live $3=backup
# PHP wordt eerst op syntax gecontroleerd; faalt dat, dan blijft alles staan.
repareer_safe() {
  if [ ! -f "$1" ]; then echo "  reparatie ontbreekt: $1"; mislukt=$((mislukt+1)); return; fi
  if [ ! -e "$2" ]; then echo "  bestaat niet meer: $2"; return; fi
  case "$2" in
    *.php|*.phtml)
      if [ -z "$PHPBIN" ]; then
        echo "  GEEN php aanwezig, syntax niet te controleren, overgeslagen: $2"
        mislukt=$((mislukt+1)); return
      fi
      if ! "$PHPBIN" -l "$1" >/dev/null 2>&1; then
        echo "  ONGELDIGE PHP na reparatie, overgeslagen: $2"
        mislukt=$((mislukt+1)); return
      fi ;;
  esac
  mkdir -p "$(dirname "$3")"
  if ! cp -p "$2" "$3"; then echo "  BACKUP MISLUKT, overgeslagen: $2"; mislukt=$((mislukt+1)); return; fi
  if cp "$1" "$2"; then gerepareerd=$((gerepareerd+1))
  else echo "  MISLUKT: $2"; mislukt=$((mislukt+1)); fi
}

# Verwijdert een WordPress-account.  $1=database $2=sql $3=omschrijving
#
# Rechtstreeks in de database, als root via de socket. Dat klinkt grover dan
# het is, en er is een goede reden voor: wp-cli moet eerst wp-config.php
# uitvoeren, en die bestanden kiezen hun databasegegevens nogal eens op basis
# van $_SERVER['HTTP_HOST']. Op de commandoregel bestaat die niet en dan komt
# wp-cli de database niet eens in.
#
# De query doet hetzelfde als wp_delete_user() met een herverdeling: berichten
# en reacties gaan eerst naar de beheerder die blijft staan, daarna pas gaan de
# metadata en het account weg. Er blijft dus niets verweesd achter.
verwijder_wp_user() {
  if [ -z "$MYSQLBIN" ]; then
    echo "  GEEN mysql-client, overgeslagen: $3"; mislukt=$((mislukt+1)); return
  fi
  uitvoer="$(printf '%s\\n' "$2" | "$MYSQLBIN" --batch --database="$1" 2>&1)"
  if [ $? -eq 0 ]; then
    echo "  verwijderd: $3"; accounts=$((accounts+1))
  else
    echo "  MISLUKT: $3"
    # De melding erbij. Zonder die regel sta je te raden.
    printf '%s\\n' "$uitvoer" | grep -v '^$' | head -3 | sed 's/^/        /'
    mislukt=$((mislukt+1))
  fi
}
'''


def schrijf_opruimscript(uitmap, installaties, salt_pad=None, salt_n=0,
                         gebr_regels=None, gebr_n=0):
    """
    Genereert twee shell-scripts die je zelf kunt lezen voordat je ze draait:

      opruimen.sh     verplaatst besmette bestanden naar quarantaine, zet
                      aangetaste originelen terug uit de cache, en zet
                      gerepareerde versies van .htaccess terug.
      terugzetten.sh  draait alle drie volledig terug.

    Alles wat overschreven wordt gaat eerst naar _origineel/. Python schrijft
    zelf niets in /home; dat doet alleen het shell-script, als jij het start.
    """
    quarantaine = os.path.join(uitmap, 'quarantaine')
    backupmap = os.path.join(uitmap, '_origineel')
    repmap = os.path.join(uitmap, 'reparaties')
    op_pad = os.path.join(uitmap, 'opruimen.sh')
    terug_pad = os.path.join(uitmap, 'terugzetten.sh')

    op = ['#!/bin/bash',
          '# Gegenereerd door wpscan.py op %s' % time.strftime('%Y-%m-%d %H:%M'),
          '#',
          '# LEES DIT SCRIPT VOORDAT JE HET DRAAIT.',
          '# Er wordt niets verwijderd. Alles is omkeerbaar met:',
          '#     bash %s --alles' % terug_pad,
          '# En een enkel bestand met:',
          '#     bash %s <stuk-van-het-pad>' % terug_pad,
          '',
          'set -u']
    op.append(SH_HULP)

    terug = ['#!/bin/bash',
             '# Draait terug wat opruimen.sh heeft gedaan.',
             '#',
             '#   bash %s' % terug_pad,
             '#       laat zien wat er terug kan. Doet verder niets.',
             '#',
             '#   bash %s functions.php' % terug_pad,
             '#       zet alleen terug wat op "functions.php" matcht.',
             '#',
             '#   bash %s --lijst gschamp' % terug_pad,
             '#       toon alleen wat op "gschamp" matcht.',
             '#',
             '#   bash %s --alles' % terug_pad,
             '#       zet alles terug.',
             '#',
             '# De zoekterm is een stuk van het volledige pad. Een gebruikersnaam',
             '# of een domein werkt dus ook: die staan er allebei in.',
             'set -u',
             '',
             'MODUS=lijst; FILTER=""; FASE=toon; JA=""',
             'terug=0; gevonden=0; quar=0; mislukt=0',
             '',
             'case "${1:-}" in',
             '  "")       MODUS=lijst ;;',
             '  --lijst)  MODUS=lijst; FILTER="${2:-}" ;;',
             '  --alles)  MODUS=zetterug ;;',
             '  -*)       echo "Onbekende optie: $1"; exit 1 ;;',
             '  *)        MODUS=zetterug; FILTER="$1" ;;',
             'esac',
             '# Tweede argument --ja slaat de bevestiging over.',
             'case "${2:-}" in --ja) JA=1 ;; esac',
             '',
             'past() {',
             '  [ -z "$FILTER" ] && return 0',
             '  case "$1" in *"$FILTER"*) return 0 ;; *) return 1 ;; esac',
             '}',
             '',
             '# $1=soort $2=ernst $3=reden $4=bron $5=live',
             '# Dezelfde regel dient om te tonen en om terug te zetten, zodat',
             '# je nooit iets anders krijgt dan wat er in de lijst stond.',
             'terug_item() {',
             '  past "$5" || return 0',
             '  gevonden=$((gevonden+1))',
             '  if [ "$FASE" = toon ]; then',
             '    [ "$1" = quarantaine ] && quar=$((quar+1))',
             '    printf "  %-12s %-9s %s\\n" "$1" "$2" "$3"',
             '    printf "      %s\\n" "$5"',
             '    return 0',
             '  fi',
             '  if [ ! -e "$4" ]; then',
             '    echo "  niets terug te zetten: $4"; mislukt=$((mislukt+1)); return 0',
             '  fi',
             '  mkdir -p "$(dirname "$5")"',
             '  if [ "$1" = quarantaine ]; then',
             '    if mv "$4" "$5"; then terug=$((terug+1)); echo "  terug: $5"',
             '    else echo "  MISLUKT: $5"; mislukt=$((mislukt+1)); fi',
             '  else',
             '    if cp -p "$4" "$5"; then terug=$((terug+1)); echo "  terug: $5"',
             '    else echo "  MISLUKT: $5"; mislukt=$((mislukt+1)); fi',
             '  fi',
             '}',
             '',
             'alle_items() {',
             '  :']

    tel = {'Quarantine': 0, 'RestoreOfficial': 0, 'FixInPlace': 0,
           'OudThema': 0, 'OudKern': 0, 'geen_bron': 0}
    secties = {'Quarantine': [], 'RestoreOfficial': [], 'FixInPlace': [],
               'OudThema': [], 'OudKern': []}
    secties_terug = {'Quarantine': [], 'RestoreOfficial': [], 'FixInPlace': [],
                     'OudThema': [], 'OudKern': []}

    for inst in installaties:
        for actie in secties:
            secties[actie].append(None)          # plaatshouder voor het kopje
            secties_terug[actie].append(None)
        start = {a: len(secties[a]) for a in secties}

        # Mappen die in hun geheel naar quarantaine gaan. Losse bestanden
        # daarbinnen krijgen geen eigen regel: de map neemt ze mee. Precies
        # dezelfde voorwaarden als hieronder, anders zou een map die alsnog
        # afvalt de bestanden erin ten onrechte als afgehandeld markeren.
        mapprefixen = tuple(
            b['pad'].rstrip('/') + '/' for b in inst.get('bevindingen', [])
            if b['pad'] and not b['pad'].startswith('/')
            and (b['actie'] == 'OudThema'
                 or (b['actie'] == 'Quarantine'
                     and b['severity'] in ('Critical', 'High')))
            and os.path.isdir(os.path.join(inst['root'], b['pad'])))

        for b in inst.get('bevindingen', []):
            # Standaard: opruimen.sh doet hier niets mee. Overal waar we wel
            # een regel schrijven zetten we dit expliciet om. Zo hoeft de lijst
            # 'zelf doen' straks niets te raden.
            b['gedaan'] = False
            actie = b['actie']
            rel = b['pad']

            if actie == 'Review':
                b['waarom_niet'] = 'review'
                continue
            if actie not in secties:
                b['waarom_niet'] = 'geen-actie'
                continue
            # Een leeg pad, een absoluut pad of een pad met '..' mag nooit in
            # een mv-regel belanden: os.path.join maakt van een leeg pad de
            # docroot zelf, en dan verplaats je de hele site.
            if not rel or rel.startswith('/') or '..' in rel.split('/'):
                b['waarom_niet'] = 'geen-pad'
                continue
            if actie == 'Quarantine' and b['severity'] not in ('Critical', 'High'):
                b['waarom_niet'] = 'alleen-ernstig'
                continue
            if rel.startswith(mapprefixen):
                # Wordt afgehandeld doordat de map eromheen wordt verplaatst.
                b['gedaan'] = True
                continue

            live = os.path.join(inst['root'], rel)
            merk = os.path.join(inst['user'], inst['domein'], rel)

            # De reden gaat mee het terugzetscript in: zie je straks een lijst
            # met wat je kunt terughalen, dan wil je weten wat het was.
            ernst = b['severity']
            reden = kort(b['reden'], 62)

            if actie in ('Quarantine', 'OudThema', 'OudKern'):
                doel = os.path.join(quarantaine, merk)
                soort_terug = {'Quarantine': 'quarantaine',
                               'OudThema': 'oud-thema',
                               'OudKern': 'oude-kern'}[actie]
                secties[actie].append('mv_safe %s %s' % (shq(live), shq(doel)))
                secties_terug[actie].append(
                    '  terug_item %s %s %s %s %s'
                    % (soort_terug, shq(ernst), shq(reden), shq(doel),
                       shq(live)))
                tel[actie] += 1
                b['gedaan'] = True

            elif actie == 'RestoreOfficial':
                schoon = b.get('schoon')
                if not schoon:
                    tel['geen_bron'] += 1
                    b['waarom_niet'] = 'geen-origineel'
                    continue
                backup = os.path.join(backupmap, merk)
                secties[actie].append('herstel_safe %s %s %s'
                                      % (shq(schoon), shq(live), shq(backup)))
                secties_terug[actie].append(
                    '  terug_item origineel %s %s %s %s'
                    % (shq(ernst), shq(reden), shq(backup), shq(live)))
                tel[actie] += 1
                b['gedaan'] = True

            elif actie == 'FixInPlace':
                herstel = b.get('herstel')
                if not herstel:
                    tel['geen_bron'] += 1
                    b['waarom_niet'] = 'reparatie'
                    continue
                repbestand = os.path.join(repmap, merk)
                os.makedirs(os.path.dirname(repbestand), exist_ok=True)
                with open(repbestand, 'w', encoding='utf-8', newline='\n') as f:
                    f.write(herstel)
                backup = os.path.join(backupmap, merk)
                secties[actie].append('repareer_safe %s %s %s'
                                      % (shq(repbestand), shq(live), shq(backup)))
                secties_terug[actie].append(
                    '  terug_item reparatie %s %s %s %s'
                    % (shq(ernst), shq(reden), shq(backup), shq(live)))
                tel[actie] += 1
                b['gedaan'] = True

        for a in secties:
            n = len(secties[a]) - start[a]
            kopje = ('# --- %s / %s (%d) ---' % (inst['user'], inst['domein'], n)
                     if n else '')
            secties[a][start[a] - 1] = kopje
            secties_terug[a][start[a] - 1] = kopje

    titels = [
        ('Quarantine', 'DEEL 1: BESMETTE BESTANDEN NAAR QUARANTAINE',
         'Deze bestanden horen er niet en kunnen weg.'),
        ('RestoreOfficial', 'DEEL 2: AANGETASTE ORIGINELEN TERUGZETTEN',
         'Deze bestanden horen er wel, maar zijn aangepast. Ze worden '
         'vervangen\n# door het officiele bestand van wordpress.org.'),
        ('FixInPlace', 'DEEL 3: GEREPAREERDE BESTANDEN TERUGZETTEN',
         'Hier zijn alleen de kwaadaardige regels uit gehaald; de rest van het\n'
         '# bestand blijft zoals het was. Vergelijk gerust eerst met diff.'),
        ('OudThema', 'DEEL 4: ONGEBRUIKTE STANDAARDTHEMA\'S OPRUIMEN',
         'Geen malware, maar code die niemand bijwerkt en die wel meedoet in\n'
         '# elk lek. Het actieve thema en zijn ouderthema blijven staan.\n'
         '# Ze gaan naar quarantaine, dus terugzetten kan altijd nog.'),
        ('OudKern', 'DEEL 5: VEROUDERDE KERNBESTANDEN OPRUIMEN',
         'Bestanden uit een oudere WordPress die bij de update hadden moeten\n'
         '# verdwijnen, maar zijn blijven staan omdat er alleen overheen is\n'
         '# gekopieerd. WordPress laadt ze niet meer. De lijst komt uit\n'
         '# $_old_files in wp-admin/includes/update-core.php van de site zelf.'),
    ]

    for sleutel, titel, uitleg in titels:
        regels = [r for r in secties[sleutel] if r]
        if not any(r for r in regels if not r.startswith('#')):
            continue
        op.extend(['', '# ' + '=' * 68, '# ' + titel, '# ' + uitleg,
                   '# ' + '=' * 68, 'echo ""; echo "%s"' % titel, ''])
        op.extend(regels)
        terugregels = [r for r in secties_terug[sleutel] if r]
        terug.extend(['', '# ' + titel, ''])
        terug.extend(terugregels)

    # Accounts als laatste ingreep op de site zelf: de bestanden zijn dan al
    # schoon, en dit is het enige deel dat terugzetten.sh niet kan terugdraaien.
    if gebr_regels and gebr_n:
        op.extend(['',
                   '# ' + '=' * 68,
                   '# DEEL 6: WORDPRESS-ACCOUNTS VERWIJDEREN',
                   '# Deze accounts heb je zelf aangewezen tijdens de scan.',
                   '# Hun berichten en reacties gaan eerst naar de beheerder',
                   '# die blijft staan, daarna pas verdwijnt het account.',
                   '# LET OP: dit is het enige deel dat NIET terug te draaien is.',
                   '# ' + '=' * 68,
                   'echo ""; echo "DEEL 6: WORDPRESS-ACCOUNTS VERWIJDEREN"',
                   ''])
        op.extend(gebr_regels)

    op.extend(['', 'echo ""',
               'echo "Klaar."',
               'echo "  $verplaatst  naar quarantaine"',
               'echo "  $hersteld  teruggezet uit het origineel"',
               'echo "  $gerepareerd  gerepareerd"',
               'echo "  $accounts  account(s) verwijderd"',
               'echo "  $mislukt  mislukt of overgeslagen"',
               'echo ""',
               'echo "Quarantaine:  %s"' % quarantaine,
               'echo "Backups:      %s"' % backupmap,
               'echo "Terugdraaien: bash %s --alles"' % terug_pad,
               'echo "Of een enkel bestand: bash %s <stuk-van-het-pad>"'
               % terug_pad,
               ''])

    # Laatste stap, en bewust een vraag: verse salts loggen iedereen uit. Dat
    # is precies de bedoeling tegen een gestolen sessiecookie, maar het is
    # niet iets wat je iemand ongevraagd aandoet.
    if salt_pad and salt_n:
        op.extend([
            '',
            '# ' + '=' * 68,
            '# DEEL 7: NIEUWE SALTS (vraag)',
            '# ' + '=' * 68,
            'echo ""',
            'echo "  ------------------------------------------------------------"',
            'echo "  Nog een stap: verse salts in wp-config.php"',
            'echo ""',
            'echo "  Dat maakt alle sessiecookies ongeldig. Een aanvaller die"',
            'echo "  nog een sessie open had staan, vliegt er nu uit."',
            'echo ""',
            'echo "  Let op: iedereen wordt uitgelogd, ook jij en je klant."',
            'echo "  Wachtwoorden veranderen hier NIET van."',
            'echo ""',
            'echo "  Klaargezet voor %d site(s)."' % salt_n,
            'echo ""',
            'if [ -t 0 ]; then',
            '  printf "  Nieuwe salts nu instellen? [j/N]: "',
            '  read -r saltantwoord',
            '  case "$saltantwoord" in',
            '    [jJ]*) echo ""; bash %s ;;' % shq(salt_pad),
            '    *) echo "  Overgeslagen. Later alsnog:  bash %s" ;;' % salt_pad,
            '  esac',
            'else',
            '  echo "  Geen terminal, dus overgeslagen."',
            '  echo "  Later alsnog:  bash %s"' % salt_pad,
            'fi',
            'echo ""',
            ''])
    terug.extend([
        '}',
        '',
        'echo ""',
        'alle_items',
        'echo ""',
        '',
        'if [ "$MODUS" = lijst ]; then',
        '  if [ "$gevonden" -eq 0 ]; then',
        '    echo "  Niets gevonden."',
        '  else',
        '    echo "  $gevonden bestand(en) kunnen terug."',
        '  fi',
        '  echo ""',
        '  echo "  Een bestand terug:  bash %s <stuk-van-het-pad>"' % terug_pad,
        '  echo "  Alles terug:        bash %s --alles"' % terug_pad,
        '  echo ""',
        '  exit 0',
        'fi',
        '',
        'if [ "$gevonden" -eq 0 ]; then',
        '  echo "  Niets gevonden dat op \\"$FILTER\\" matcht."',
        '  echo "  Kijk met:  bash %s"' % terug_pad,
        '  exit 0',
        'fi',
        '',
        '# Bestanden uit quarantaine zijn ooit als malware aangemerkt. Dat is',
        '# geen reden om ze niet terug te zetten, wel om het te zeggen.',
        'if [ "$quar" -gt 0 ]; then',
        '  echo "  LET OP: $quar hiervan stond in quarantaine als malware."',
        '  echo ""',
        'fi',
        'if [ -z "$JA" ]; then',
        '  if [ ! -t 0 ]; then',
        '    echo "  Geen terminal om te bevestigen, dus niets gedaan."',
        '    echo "  Bedoel je het echt, zet er dan --ja achter."',
        '    exit 1',
        '  fi',
        '  printf "  %s bestand(en) terugzetten? [j/N]: " "$gevonden"',
        '  read -r antwoord',
        '  case "$antwoord" in',
        '    [jJ]*) ;;',
        '    *) echo "  Niets gedaan."; exit 0 ;;',
        '  esac',
        'fi',
        'echo ""',
        '',
        'FASE=doen',
        'alle_items',
        'echo ""',
        'echo "  $terug teruggezet, $mislukt mislukt of niet gevonden."',
        'echo "  Kernbestanden die ontbraken en zijn teruggeplaatst, blijven"',
        'echo "  staan -- dat zijn originelen van wordpress.org."',
        ''])

    for pad, regels in ((op_pad, op), (terug_pad, terug)):
        with open(pad, 'w', encoding='utf-8', newline='\n') as f:
            f.write('\n'.join(regels))
        os.chmod(pad, 0o700)

    return op_pad, terug_pad, tel


SALT_NAMEN = ('AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY',
              'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT')


def haal_salts():
    """
    Haalt een verse set salts op bij wordpress.org. Elke site moet zijn eigen
    set krijgen, dus dit wordt per site opnieuw aangeroepen.

    De regels worden letterlijk overgenomen zoals de API ze teruggeeft; de
    waarden zelf ontleden we niet, want daar zitten aanhalingstekens en
    backslashes in die je alleen maar stuk kunt maken.
    """
    try:
        req = urllib.request.Request(
            'https://api.wordpress.org/secret-key/1.1/salt/',
            headers={'User-Agent': USER_AGENT})
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            tekst = r.read().decode('utf-8', 'replace')
    except Exception:
        return None

    regels = {}
    for regel in tekst.splitlines():
        m = re.match(r"\s*define\s*\(\s*'(\w+)'\s*,", regel)
        if m and m.group(1) in SALT_NAMEN and regel.rstrip().endswith(');'):
            regels[m.group(1)] = regel.strip()
    return regels if len(regels) == len(SALT_NAMEN) else None


def vervang_salts(tekst, saltregels):
    """
    Vervangt de acht salt-defines in een wp-config.php.

    Alleen als ze alle acht precies een keer voorkomen. In elk ander geval
    doen we niets en zeggen we waarom: wp-config.php is het laatste bestand
    waar je gokwerk in wilt hebben, en sommige installaties halen hun salts
    ergens anders vandaan.

    Geeft (nieuwe_tekst, None) of (None, reden).
    """
    nieuw = tekst
    for naam in SALT_NAMEN:
        rx = re.compile(r"^[ \t]*define\s*\(\s*['\"]" + naam
                        + r"['\"]\s*,.*\)\s*;[ \t]*$", re.M)
        aantal = len(rx.findall(nieuw))
        if aantal == 0:
            return None, 'define voor %s niet gevonden' % naam
        if aantal > 1:
            return None, '%s staat %d keer in het bestand' % (naam, aantal)
        # Vervangen via een functie, niet via een string: in de saltwaarden
        # zitten backslashes die re.sub anders als \1-verwijzing leest.
        nieuw = rx.sub(lambda m, n=naam: saltregels[n], nieuw, count=1)
    return nieuw, None


def schrijf_saltscript(uitmap, installaties):
    """
    Zet per site een wp-config.php met verse salts klaar, plus een script dat
    ze terugzet. Los van opruimen.sh, want dit logt iedereen uit en dat doe je
    op een gekozen moment.
    """
    saltmap = os.path.join(uitmap, 'nieuwe-salts')
    backupmap = os.path.join(uitmap, '_origineel')
    pad = os.path.join(uitmap, 'nieuwe-salts.sh')

    regels = ['#!/bin/bash',
              '# Gegenereerd door wpscan.py op %s' % time.strftime('%Y-%m-%d %H:%M'),
              '#',
              '# Vervangt de salts in wp-config.php door een verse set van',
              '# wordpress.org. Gevolg: iedereen wordt uitgelogd, ook een',
              '# aanvaller met een gestolen sessiecookie. Wachtwoorden',
              '# veranderen hier NIET van.',
              '#',
              '# De oude wp-config.php gaat eerst naar _origineel/.',
              '',
              'set -u',
              'PHPBIN="$(command -v php 2>/dev/null || echo \'\')"',
              'gedaan=0; mislukt=0',
              '',
              'zet_salts() {  # $1=nieuw $2=live $3=backup',
              '  if [ ! -f "$1" ] || [ ! -f "$2" ]; then',
              '    echo "  overgeslagen: $2"; mislukt=$((mislukt+1)); return; fi',
              '  if [ -z "$PHPBIN" ]; then',
              '    echo "  geen php om te controleren, overgeslagen: $2"',
              '    mislukt=$((mislukt+1)); return; fi',
              '  if ! "$PHPBIN" -l "$1" >/dev/null 2>&1; then',
              '    echo "  ONGELDIGE PHP, overgeslagen: $2"',
              '    mislukt=$((mislukt+1)); return; fi',
              '  mkdir -p "$(dirname "$3")"',
              '  if ! cp -p "$2" "$3"; then',
              '    echo "  BACKUP MISLUKT, overgeslagen: $2"',
              '    mislukt=$((mislukt+1)); return; fi',
              '  if cp "$1" "$2"; then gedaan=$((gedaan+1)); echo "  nieuwe salts: $2"',
              '  else echo "  MISLUKT: $2"; mislukt=$((mislukt+1)); fi',
              '}',
              '']

    klaar, overgeslagen = 0, []
    for inst in installaties:
        if inst.get('soort') == 'los':
            continue          # geen WordPress, dus geen salts
        config = os.path.join(inst['root'], 'wp-config.php')
        if not os.path.isfile(config):
            # WordPress staat toe dat wp-config.php een map hoger staat.
            config = os.path.join(os.path.dirname(inst['root']), 'wp-config.php')
            if not os.path.isfile(config):
                overgeslagen.append((inst['domein'], 'geen wp-config.php gevonden'))
                continue

        origineel = lees_tekst_exact(config)
        if origineel is None:
            overgeslagen.append((inst['domein'], 'wp-config.php is geen geldige UTF-8'))
            continue

        salts = haal_salts()
        if not salts:
            overgeslagen.append((inst['domein'], 'kon geen salts ophalen bij wordpress.org'))
            continue

        nieuw, fout = vervang_salts(origineel, salts)
        if nieuw is None:
            overgeslagen.append((inst['domein'], fout))
            continue

        doel = os.path.join(saltmap, inst['user'], inst['domein'], 'wp-config.php')
        os.makedirs(os.path.dirname(doel), exist_ok=True)
        with open(doel, 'w', encoding='utf-8', newline='\n') as f:
            f.write(nieuw)
        os.chmod(doel, 0o600)

        backup = os.path.join(backupmap, inst['user'], inst['domein'],
                              'wp-config.php.voor-salts')
        regels.append('# --- %s ---' % inst['domein'])
        regels.append('zet_salts %s %s %s'
                      % (shq(doel), shq(config), shq(backup)))
        regels.append('')
        klaar += 1

    regels.extend(['echo ""',
                   'echo "Klaar. $gedaan aangepast, $mislukt overgeslagen."',
                   'echo "Iedereen is nu uitgelogd. Dat hoort zo."',
                   ''])

    with open(pad, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(regels))
    os.chmod(pad, 0o700)
    return pad, klaar, overgeslagen


def shq(s):
    """Enkelquote een pad voor shell-gebruik."""
    return "'" + str(s).replace("'", "'\\''") + "'"


# ---------------------------------------------------------------------------
# Interactieve keuzes
# ---------------------------------------------------------------------------

def kies_omvang(inventaris):
    """Alles of een specifieke user? Dit is de eerste vraag."""
    kop('WAT WIL JE SCANNEN?')
    tot_inst = sum(len(u['installaties']) for u in inventaris)
    print('  Gevonden: %s user(s) met WordPress, %s installatie(s) in totaal.'
          % (c(str(len(inventaris)), 'vet'), c(str(tot_inst), 'vet')))
    print('')
    print('   1   ' + c('alle users', 'vet') + ' (per user wordt gevraagd of je hem doet)')
    print('   2   een ' + c('specifieke user', 'vet'))
    print('   3   alleen de ' + c('lijst tonen', 'vet') + ', nu niet scannen')
    print('')

    while True:
        keuze = vraag('  Je keuze [1]: ') or '1'
        if keuze == '1':
            return 'alle', None
        if keuze == '3':
            return 'lijst', None
        if keuze == '2':
            return 'een', kies_user(inventaris)
        print(c('  Kies 1, 2 of 3.', 'geel'))


def kies_user(inventaris):
    kop('WELKE USER?')
    for nr, u in enumerate(inventaris, 1):
        domeinen = ', '.join(sorted(set(i['domein'] for i in u['installaties'])))
        if len(domeinen) > 52:
            domeinen = domeinen[:49] + '...'
        print('  %3d  %-16s %2d installatie(s)  %s'
              % (nr, u['user'], len(u['installaties']), c(domeinen, 'grijs')))
    print('')
    while True:
        antwoord = vraag('  Nummer of usernaam: ')
        if _INVOER_OP[0]:
            print(c('  Geen invoer beschikbaar. Gebruik --user <naam>.', 'geel'))
            sys.exit(1)
        if not antwoord:
            continue
        if antwoord.isdigit() and 1 <= int(antwoord) <= len(inventaris):
            return inventaris[int(antwoord) - 1]['user']
        for u in inventaris:
            if u['user'] == antwoord:
                return antwoord
        print(c('  Niet gevonden. Probeer het nummer uit de lijst.', 'geel'))


def vraag_per_user(u, nr, totaal):
    """Per user: scannen of overslaan. Geeft 'ja'/'nee'/'rest'/'stop' terug."""
    print('')
    print(c('-' * 74, 'grijs'))
    print('  User %d van %d:  %s' % (nr, totaal, c(u['user'], 'vet')))
    for inst in u['installaties']:
        print('      %-44s %s' % (inst_naam(inst)[:44], soort_label(inst)))
    print('')
    print('   [Enter] scannen      O overslaan')
    print('   A       vanaf hier alles scannen zonder verder te vragen')
    print('   S       stoppen')
    antwoord = vraag('  Je keuze: ').upper()
    if antwoord == 'O':
        return 'nee'
    if antwoord == 'A':
        return 'rest'
    if antwoord == 'S':
        return 'stop'
    return 'ja'


# ---------------------------------------------------------------------------
# Hoofdprogramma
# ---------------------------------------------------------------------------

def db_gegevens(configpad):
    """Leest DB_NAME en $table_prefix uit een wp-config.php."""
    tekst = lees_tekst(configpad, 200000)
    m = re.search(r"define\s*\(\s*['\"]DB_NAME['\"]\s*,\s*['\"](.*?)['\"]\s*\)",
                  tekst)
    naam = m.group(1) if m else None
    prefix = 'wp_'
    m = re.search(r"\$table_prefix\s*=\s*['\"]([^'\"]+)['\"]", tekst)
    if m:
        prefix = m.group(1)
    # Het prefix gaat rechtstreeks in een query, dus alleen nette tekens.
    if not re.match(r'^[A-Za-z0-9_]+$', prefix):
        return None, None
    return naam, prefix


def mysql_rijen(db, sql):
    """
    Draait een query als root via de mysql-client. Zo hoeven we het
    databasewachtwoord van de site niet uit te lezen: root komt binnen via de
    socket. Geeft None als er geen client is of de query faalt.
    """
    for exe in ('mariadb', 'mysql'):
        try:
            uit = subprocess.check_output(
                [exe, '-N', '-B', '--database', db, '-e', sql],
                stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            continue
        except (subprocess.CalledProcessError, OSError):
            return None
        regels = uit.decode('utf-8', 'replace').splitlines()
        return [r.split('\t') for r in regels if r]
    return None


def wp_gebruikers(inst):
    """De WordPress-gebruikers van een installatie, of None."""
    config = os.path.join(inst['root'], 'wp-config.php')
    if not os.path.isfile(config):
        config = os.path.join(os.path.dirname(inst['root']), 'wp-config.php')
        if not os.path.isfile(config):
            return None
    db, prefix = db_gegevens(config)
    if not db:
        return None
    inst['db'] = db
    inst['prefix'] = prefix

    sql = ("SELECT u.ID, u.user_login, u.user_email, u.user_registered,"
           " COALESCE(m.meta_value, ''),"
           " (SELECT COUNT(*) FROM {p}posts p WHERE p.post_author = u.ID"
           "  AND p.post_status <> 'auto-draft')"
           " FROM {p}users u"
           " LEFT JOIN {p}usermeta m ON m.user_id = u.ID"
           "  AND m.meta_key = '{p}capabilities'"
           " ORDER BY u.ID").format(p=prefix)

    rijen = mysql_rijen(db, sql)
    if rijen is None:
        return None

    gebruikers = []
    for r in rijen:
        if len(r) < 6:
            continue
        rollen = re.findall(r's:\d+:"([^"]+)";b:1', r[4]) or ['(geen rol)']
        gebruikers.append({
            'id': r[0], 'login': r[1], 'email': r[2],
            'geregistreerd': r[3][:10], 'rollen': rollen,
            'berichten': r[5], 'admin': 'administrator' in rollen,
        })
    return gebruikers


def tabel_bestaat(inst, naam):
    return bool(mysql_rijen(inst['db'], "SHOW TABLES LIKE '%s'" % naam))


def sql_verwijder_gebruiker(prefix, gid, naar, met_links):
    """
    Doet in SQL precies wat wp_delete_user() met een herverdeling doet:
    berichten, reacties en eventuele links naar de beheerder die blijft, en
    daarna pas de metadata en het account zelf.

    In een transactie, zodat je nooit met een half verwijderd account blijft
    zitten: gaat er iets mis, dan stopt de client en wordt er niets bewaard.
    """
    p = prefix
    stappen = ['START TRANSACTION',
               'UPDATE %sposts SET post_author=%s WHERE post_author=%s'
               % (p, naar, gid),
               'UPDATE %scomments SET user_id=%s WHERE user_id=%s'
               % (p, naar, gid)]
    if met_links:
        stappen.append('UPDATE %slinks SET link_owner=%s WHERE link_owner=%s'
                       % (p, naar, gid))
    stappen.extend(['DELETE FROM %susermeta WHERE user_id=%s' % (p, gid),
                    'DELETE FROM %susers WHERE ID=%s' % (p, gid),
                    'COMMIT'])
    return ';\n'.join(stappen) + ';'


def vroegste_inbraak(inst):
    """Vroegste tijdstip van een bevestigde besmetting, of None."""
    tijden = [b['mtime'] for b in inst.get('bevindingen', [])
              if b.get('mtime') and b['severity'] in ('Critical', 'High')]
    return min(tijden) if tijden else None


# Rollen die ergens recht op geven, plus het geval zonder rol. Precies de
# accounts waar je na een inbraak naar wilt kijken; 'customer' en 'subscriber'
# staan er bewust niet bij: die zie je nooit, tenzij je erom vraagt.
RECHTEN_ROLLEN = ('administrator', 'editor', 'author', 'contributor',
                  'shop_manager', 'seo_manager', 'seo_editor', '(geen rol)')

# Rechteloze accounts van na de inbraak tonen we alleen als het er weinig zijn.
# Op een drukke webshop schrijft zich elke dag een klant in en zegt 'na de
# inbraak' niets meer; op een stille site is het juist het signaal.
NIEUW_MAX = 10


def rollen_telling(gebruikers):
    """'1487x customer, 10x subscriber, 3x administrator'."""
    telling = {}
    for g in gebruikers:
        for rol in g['rollen']:
            telling[rol] = telling.get(rol, 0) + 1
    op_aantal = sorted(telling.items(), key=lambda p: (-p[1], p[0]))
    tekst = ', '.join('%dx %s' % (n, rol) for rol, n in op_aantal[:8])
    if len(op_aantal) > 8:
        tekst += ', ...'
    return tekst


def opvallende_gebruikers(gebruikers, inbraak):
    """
    Wie je na een inbraak echt wilt zien: alles met rechten of zonder
    herkenbare rol, plus een handjevol rechteloze accounts van na de inbraak.
    Van 1500 webshopklanten blijft er zo een lijstje van een paar regels over.

    De volgorde van 'gebruikers' blijft behouden: het nummer dat je straks
    intypt hoort bij deze lijst, niet bij de database.
    """
    grens = (time.strftime('%Y-%m-%d', time.localtime(inbraak))
             if inbraak else None)
    rechten_ids = set(g['id'] for g in gebruikers
                      if any(rol in RECHTEN_ROLLEN for rol in g['rollen']))
    nieuw_ids = set()
    if grens:
        nieuw_ids = set(g['id'] for g in gebruikers
                        if g['id'] not in rechten_ids
                        and g['geregistreerd'] >= grens)
        if len(nieuw_ids) > NIEUW_MAX:
            nieuw_ids = set()
    kies = rechten_ids | nieuw_ids
    return [g for g in gebruikers if g['id'] in kies]


def kies_gebruikers(installaties):
    """
    Toont per site de WordPress-gebruikers en vraagt welke weg moeten. Geeft
    shell-regels terug die in opruimen.sh terechtkomen; hier wordt niets
    verwijderd. Dat gebeurt pas als jij opruimen.sh start.
    """
    regels = []
    totaal_weg = 0
    for inst in installaties:
        if inst.get('soort') == 'los':
            continue          # geen WordPress, dus ook geen accounts
        gebruikers = wp_gebruikers(inst)
        naam = inst_naam(inst)
        print('')
        print(c('  == %s' % naam, 'vet'))
        if gebruikers is None:
            print(c('     Kon de database niet uitlezen; overgeslagen.', 'geel'))
            continue
        if not gebruikers:
            print('     Geen gebruikers gevonden.')
            continue
        # Bij multisite staat de gebruikerstabel voor het hele netwerk en zit
        # de rol per site in een eigen metasleutel. Daar met de hand in
        # schrijven gaat vroeg of laat mis, dus dat doen we niet.
        if tabel_bestaat(inst, inst['prefix'] + 'blogs'):
            print(c('     Netwerkinstallatie (multisite): accounts opruimen '
                    'sla ik hier over.', 'geel'))
            continue

        inbraak = vroegste_inbraak(inst)
        opvallend = opvallende_gebruikers(gebruikers, inbraak)
        if not opvallend:
            print('     %d gebruikers, geen enkele met rechten. Niets te doen.'
                  % len(gebruikers))
            continue

        # De klanten van een webshop hoef je nooit te zien. Wil je ze toch,
        # dan typ je A; dan wordt de lijst opnieuw getekend en opnieuw
        # genummerd. Dat hernummeren is precies waarom de nummers hieronder
        # alleen als index in 'zichtbaar' gebruikt worden en nooit als ID.
        toon_alles = False
        while True:
            zichtbaar = gebruikers if toon_alles else opvallend
            verborgen = len(gebruikers) - len(zichtbaar)

            print('     %d gebruikers: %s'
                  % (len(gebruikers), rollen_telling(gebruikers)))
            if verborgen:
                print('     ' + c('%d met rechten of van net na de inbraak; '
                                  '%d klant-/abonnee-account(en) verborgen.'
                                  % (len(zichtbaar), verborgen), 'grijs'))
            print('')
            for nr, g in enumerate(zichtbaar, 1):
                let_op = ''
                if inbraak and g['geregistreerd'] >= time.strftime(
                        '%Y-%m-%d', time.localtime(inbraak)):
                    let_op = c('  <- aangemaakt na de inbraak', 'rood')
                elif g['admin'] and g['berichten'] == '0':
                    let_op = c('  <- beheerder zonder berichten', 'geel')
                print('   %3d  ID %-5s %-16s %-30s %s  %4s ber.%s'
                      % (nr, g['id'], g['login'][:16], g['email'][:30],
                         g['geregistreerd'], g['berichten'], let_op))
                print('        %s' % c(', '.join(g['rollen']), 'grijs'))

            print('')
            print('   Welke nummers moeten WEG? Scheid ze met ;')
            if verborgen:
                print('   A = ook de %d verborgen accounts tonen' % verborgen)
            print('   [Enter] = niemand verwijderen, O = site overslaan')
            antwoord = vraag('   Verwijderen: ')
            if antwoord.upper() == 'A' and verborgen:
                toon_alles = True
                print('')
                continue
            break

        if not antwoord or antwoord.upper() == 'O':
            print('     Niemand verwijderd.')
            continue

        gekozen = set()
        onbekend = []
        for stuk in re.split(r'[;,\s]+', antwoord):
            if not stuk:
                continue
            if stuk.isdigit() and 1 <= int(stuk) <= len(zichtbaar):
                gekozen.add(int(stuk))
            else:
                onbekend.append(stuk)
        if onbekend:
            print(c('     Niet herkend, dus genegeerd: %s'
                    % ', '.join(onbekend[:10]), 'geel'))
        if not gekozen:
            print(c('     Niets herkend in je antwoord; niemand verwijderd.',
                    'geel'))
            continue

        # Het getypte nummer is een plaats in de getoonde lijst. Vanaf hier
        # werken we alleen nog met g['id'] uit de database.
        weg = [zichtbaar[i - 1] for i in sorted(gekozen)]
        weg_ids = set(g['id'] for g in weg)
        # Over alle gebruikers, niet alleen de getoonde: wie je niet te zien
        # kreeg blijft gewoon staan en telt dus mee als 'blijft'.
        blijft = [g for g in gebruikers if g['id'] not in weg_ids]

        beheerders = [g for g in blijft if g['admin']]
        if not beheerders:
            print(c('     STOP: dan blijft er geen enkele beheerder over. Dan '
                    'kun je niet meer bij je eigen site. Overgeslagen.', 'rood'))
            continue

        naar = beheerders[0]
        print('')
        print('     Dit gaat weg (%d):' % len(weg))
        # Het nummer dat je typte naast het database-ID dat straks in de query
        # belandt. Zo zie je in een oogopslag of je de goede te pakken hebt.
        for nr, g in zip(sorted(gekozen), weg):
            print('       nr %-3d -> ID %-5s %-16s %-30s %s'
                  % (nr, g['id'], g['login'][:16], g['email'][:30],
                     c(', '.join(g['rollen']), 'grijs')))
        print('     Berichten gaan naar: %s (ID %s)' % (naar['login'], naar['id']))

        admins_weg = [g for g in weg if g['admin']]
        if admins_weg:
            print(c('     Let op: hier zitten %d beheerder(s) bij: %s'
                    % (len(admins_weg),
                       ', '.join(g['login'] for g in admins_weg)), 'geel'))
        if not vraag('     Aan opruimen.sh toevoegen? [j/N]: ').upper(
                ).startswith('J'):
            print('     Overgeslagen.')
            continue

        # De ID's komen uit de database, maar ze gaan zo weer een query in.
        # Alleen cijfers doorlaten kost niets en sluit dat helemaal af.
        if not str(naar['id']).isdigit():
            print(c('     Onverwacht beheerders-ID; overgeslagen.', 'rood'))
            continue
        met_links = tabel_bestaat(inst, inst['prefix'] + 'links')

        regels.append('# --- %s (%d) ---' % (naam, len(weg)))
        gezet = 0
        for g in weg:
            if not str(g['id']).isdigit():
                continue
            # Via kort() zodat een rare login nooit uit de commentaarregel
            # kan breken: dat plet ook eventuele regeleindes.
            regels.append('# %-20s %-30s [%s]'
                          % (kort(g['login'], 20), kort(g['email'], 30),
                             kort(', '.join(g['rollen']), 40)))
            regels.append('verwijder_wp_user %s %s %s'
                          % (shq(inst['db']),
                             shq(sql_verwijder_gebruiker(inst['prefix'],
                                                         g['id'], naar['id'],
                                                         met_links)),
                             shq('%s (ID %s) op %s'
                                 % (kort(g['login'], 32), g['id'], naam))))
            gezet += 1
        regels.append('')
        totaal_weg += gezet
        print('     ' + c('Toegevoegd aan opruimen.sh. Er is nog niets '
                          'verwijderd.', 'groen'))

    return regels, totaal_weg


# Op het scherm kappen we af, anders scrollt de scanuitvoer eruit. Het bestand
# zelf is altijd compleet.
SCHERM_PER_SITE = 6
SCHERM_TOTAAL = 40


# Code -> (kort label voor op het scherm, volledige uitleg voor in het bestand).
# Gescheiden gehouden omdat een afgekapte zin ('staat op Review: automatisch
# opruimen zou de s') niets zegt en alleen maar ergert.
WAAROM = {
    'review': (
        'zelf beoordelen',
        'staat op Review: automatisch opruimen zou de site kunnen breken, '
        'hier moet een mens naar kijken'),
    'geen-origineel': (
        'geen origineel',
        'er is geen schoon origineel om mee te vervangen; dit is een premium '
        'plugin of een maatwerkthema'),
    'reparatie': (
        'reparatie onveilig',
        'de kwade regels waren niet te isoleren zonder de rest van het bestand '
        'te raken'),
    'alleen-ernstig': (
        'alleen Critical/High',
        'alleen Critical en High worden verplaatst; deze bevinding is lager '
        'ingeschaald'),
    'geen-pad': (
        'samenvatting',
        'samenvattende bevinding zonder los bestandspad; er is niets om te '
        'verplaatsen'),
    'geen-actie': (
        'geen actie',
        'voor deze soort bevinding stelt het script geen ingreep voor'),
}


def waarom_kort(b):
    return WAAROM.get(b.get('waarom_niet'), ('zelf nakijken', ''))[0]


def waarom_lang(b):
    code = b.get('waarom_niet')
    if code in WAAROM:
        return WAAROM[code][1]
    return 'staat niet in opruimen.sh; kijk hier zelf naar'


def niet_gedaan(installaties, server_bev):
    """
    Elke Critical/High waar opruimen.sh niets mee doet, met de site erbij.

    Dit is de lijst die je anders met de hand uit opruimen.sh moest afleiden.
    Hij komt niet uit een gok maar uit het script zelf: elke bevinding waar een
    regel voor geschreven is, is gemarkeerd als gedaan.
    """
    rijen = [('server', b) for b in server_bev
             if b['severity'] in ('Critical', 'High') and not b.get('gedaan')]
    for inst in installaties:
        naam = inst_naam(inst)
        rijen += [(naam, b) for b in inst.get('bevindingen', [])
                  if b['severity'] in ('Critical', 'High')
                  and not b.get('gedaan')]
    return sorted(rijen, key=lambda r: (r[0], SEV_VOLGORDE[r[1]['severity']],
                                        r[1]['pad'] or ''))


def schrijf_zelfdoen(uitmap, rijen):
    """Dezelfde lijst als op het scherm, maar compleet en na te lezen."""
    pad = os.path.join(uitmap, 'zelf-doen.txt')
    regels = [
        'ZELF BEOORDELEN',
        '=' * 74,
        '',
        'Critical- en High-bevindingen waar opruimen.sh niets mee doet,',
        'met per regel de reden waarom niet. Gegenereerd op %s.'
        % time.strftime('%Y-%m-%d %H:%M'),
        '',
        'Totaal: %d' % len(rijen),
    ]
    vorig = None
    for naam, b in rijen:
        if naam != vorig:
            regels.extend(['', '', '--- %s ' % naam + '-' * max(0, 68 - len(naam))])
            vorig = naam
        regels.append('')
        regels.append('  %-8s %s' % (b['severity'], b['pad'] or '(hele site)'))
        regels.append('           waarom niet: %s' % waarom_lang(b))
        regels.append('           %s' % kort(b['reden'], 96))
        for bewijs in (b.get('bewijs') or [])[:4]:
            regels.append('             %s' % kort(bewijs, 94))
    regels.append('')
    with open(pad, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(regels))
    return pad


def toon_zelfdoen(rijen, pad):
    """De lijst op het scherm, afgekapt maar met de aantallen erbij."""
    print('')
    print('  ' + c('-' * 70, 'grijs'))
    print('  ' + c('HIER DOET OPRUIMEN.SH NIETS MEE (%d)' % len(rijen), 'vet'))
    print('  ' + c('-' * 70, 'grijs'))

    vorig, per_site, getoond = None, 0, 0
    for naam, b in rijen:
        if naam != vorig:
            if vorig is not None and per_site > SCHERM_PER_SITE:
                print('      %s' % c('... en %d meer op deze site'
                                     % (per_site - SCHERM_PER_SITE), 'grijs'))
            print('    %s' % c(naam, 'vet'))
            vorig, per_site = naam, 0
        per_site += 1
        if per_site > SCHERM_PER_SITE or getoond >= SCHERM_TOTAAL:
            continue
        getoond += 1
        # De opvulling zit binnen de kleurcodes, anders loopt de uitlijning
        # scheef zodra er een ANSI-code tussen staat.
        print('      %s %-21s %s'
              % (c('%-8s' % b['severity'], sev_kleur(b['severity'])),
                 waarom_kort(b), b['pad'] or '(hele site)'))
        for bewijs in (b.get('bewijs') or [])[:1]:
            print('             %s' % c(kort(bewijs, 92), 'grijs'))
    if vorig is not None and per_site > SCHERM_PER_SITE:
        print('      %s' % c('... en %d meer op deze site'
                             % (per_site - SCHERM_PER_SITE), 'grijs'))

    print('')
    if len(rijen) > getoond:
        print('  Volledige lijst (%d regels): %s' % (len(rijen), c(pad, 'vet')))
    else:
        print('  Ook na te lezen in: %s' % c(pad, 'vet'))


def vorige_run(werkmap, huidige_stempel):
    """Pad naar de bevindingen.json van de meest recente eerdere run."""
    kandidaten = []
    try:
        for naam in sorted(os.listdir(werkmap)):
            if naam == huidige_stempel:
                continue
            pad = os.path.join(werkmap, naam, 'bevindingen.json')
            if os.path.isfile(pad):
                kandidaten.append(pad)
    except OSError:
        return None
    return kandidaten[-1] if kandidaten else None


def lees_sleutels(jsonpad):
    """
    {(domein, pad, categorie)} van een eerdere run, om tegen af te zetten.
    De ernst zit er bewust niet in: dan zou een bevinding die van High naar
    Critical gaat als 'nieuw' gelden terwijl het hetzelfde bestand is.
    """
    try:
        with open(jsonpad, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception:
        return None
    sleutels = set()
    for inst in data.get('installaties', []):
        for b in inst.get('bevindingen', []):
            sleutels.add((inst.get('domein'), b.get('pad'), b.get('categorie')))
    return sleutels


def main():
    p = argparse.ArgumentParser(
        description='WordPress-vlootscanner voor DirectAdmin (alleen lezen).')
    p.add_argument('--user', help='scan alleen deze DirectAdmin-user')
    p.add_argument('--all', action='store_true',
                   help='scan alle users zonder per user te vragen')
    p.add_argument('--yes', action='store_true',
                   help='stel geen vragen (voor in cron)')
    p.add_argument('--lijst', action='store_true',
                   help='toon alleen wat er gevonden is, scan niet')
    p.add_argument('--offline', action='store_true',
                   help='niet vergelijken met wordpress.org (alleen handtekeningen)')
    p.add_argument('--geen-salts', dest='geen_salts', action='store_true',
                   help='geen verse salts klaarzetten (standaard vraagt '
                        'opruimen.sh er aan het eind om)')
    p.add_argument('--geen-gebruikers', dest='geen_gebruikers',
                   action='store_true',
                   help='de WordPress-gebruikers niet nalopen na de scan')
    p.add_argument('--sinds', metavar='BEVINDINGEN.JSON',
                   help='vergelijk met deze eerdere run en toon wat nieuw is')
    p.add_argument('--sinds-vorige', dest='sinds_vorige', action='store_true',
                   help='vergelijk met de vorige run in dezelfde map')
    p.add_argument('--stil', action='store_true',
                   help='druk niets af tenzij er nieuwe Critical/High is '
                        '(voor in cron: geen nieuws = geen mail)')
    p.add_argument('--uit', default=WORK_DIR, help='map voor het rapport')
    args = p.parse_args()

    if not args.stil:
        return _run(args)

    # Stil zonder vergelijking zou nooit iets afdrukken. Dan is vergelijken
    # met de vorige run wat je bedoelt.
    if not args.sinds:
        args.sinds_vorige = True

    # In cron wil je alleen mail als er iets is. Cron mailt de uitvoer van een
    # taak, dus 'niets afdrukken' is precies 'geen mail'. De uitvoer gaat in
    # een buffer en wordt alleen echt geschreven als er nieuws is - of als er
    # iets misging, want een scan die stilletjes faalt is erger dan geen scan.
    buffer, echt = io.StringIO(), sys.stdout
    sys.stdout = buffer
    try:
        code = _run(args)
    except Exception:
        sys.stdout = echt
        echt.write(buffer.getvalue())
        raise
    finally:
        sys.stdout = echt
    if code != 0:
        echt.write(buffer.getvalue())
    return code


def _run(args):
    if os.geteuid() != 0:
        print(c('  Let op: je draait niet als root. Je ziet dan alleen de '
                'sites waar je bij kunt.', 'geel'))

    kop('WORDPRESS-VLOOTSCAN')
    print('  Deze versie leest alleen. Er wordt niets gewijzigd of verwijderd')
    print('  in /home. Het opruimen gebeurt met een apart shell-script dat je')
    print('  eerst zelf kunt nakijken.')

    os.makedirs(CACHE_DIR, exist_ok=True)
    stempel = time.strftime('%Y%m%d-%H%M%S')
    uitmap = os.path.join(args.uit, stempel)
    os.makedirs(uitmap, exist_ok=True)

    print('')
    print('  Inventariseren...')
    users = da_users()
    if not users:
        print(c('  Geen DirectAdmin-users gevonden onder %s of %s.'
                % (DA_USERS_DIR, HOME_DIR), 'rood'))
        return 1
    inventaris = inventariseer(users)
    if not inventaris:
        print(c('  Geen WordPress-installaties gevonden.', 'geel'))
        return 0

    # -- Bepalen wat er gescand wordt --------------------------------------
    interactief = not (args.yes or args.all or args.user or args.lijst)

    if args.lijst:
        modus, doel = 'lijst', None
    elif args.user:
        modus, doel = 'een', args.user
    elif args.all or args.yes:
        modus, doel = 'rest', None
    else:
        modus, doel = kies_omvang(inventaris)

    if modus == 'lijst':
        kop('GEVONDEN INSTALLATIES')
        for u in inventaris:
            print('  %s' % c(u['user'], 'vet'))
            for inst in u['installaties']:
                print('      %-48s %s' % (inst_naam(inst)[:48],
                                          soort_label(inst)))
        print('')
        print('  Totaal: %d user(s), %d installatie(s).'
              % (len(inventaris), sum(len(u['installaties']) for u in inventaris)))
        return 0

    if modus == 'een':
        # --user accepteert zowel de naam als het nummer uit de lijst, net als
        # de interactieve vraag. Anders werkt wat je net getypt hebt ineens
        # niet meer als parameter.
        gekozen = doel
        if gekozen.isdigit() and 1 <= int(gekozen) <= len(inventaris):
            gekozen = inventaris[int(gekozen) - 1]['user']
        gefilterd = [u for u in inventaris if u['user'] == gekozen]
        if not gefilterd:
            print(c('  Geen user "%s" met WordPress gevonden.' % doel, 'geel'))
            print('')
            print('  Beschikbaar:')
            for nr, u in enumerate(inventaris, 1):
                print('    %3d  %-16s %d installatie(s)'
                      % (nr, u['user'], len(u['installaties'])))
            return 1
        if gekozen != doel:
            print('  Nummer %s = user %s' % (doel, c(gekozen, 'vet')))
        inventaris = gefilterd

    # -- Per user vragen ----------------------------------------------------
    te_scannen = []
    vraag_nog = interactief and modus == 'alle'
    for nr, u in enumerate(inventaris, 1):
        if not vraag_nog:
            te_scannen.append(u)
            continue
        antwoord = vraag_per_user(u, nr, len(inventaris))
        if antwoord == 'stop':
            break
        if antwoord == 'rest':
            vraag_nog = False
            te_scannen.append(u)
            continue
        if antwoord == 'ja':
            te_scannen.append(u)

    if not te_scannen:
        print('')
        print('  Niets geselecteerd. Gestopt.')
        return 0

    # -- Scannen ------------------------------------------------------------
    kop('SCANNEN')
    alle_installaties = []
    server_bev = scan_server_breed()
    begin = time.time()

    totaal_inst = sum(len(u['installaties']) for u in te_scannen)
    teller = 0

    for u in te_scannen:
        for inst in u['installaties']:
            teller += 1
            naam = inst_naam(inst)
            sys.stdout.write('  [%d/%d] %-44s ' % (teller, totaal_inst, naam[:44]))
            sys.stdout.flush()
            try:
                scan_installatie(inst, offline=args.offline)
            except Exception as e:
                print(c('FOUT: %s' % e, 'rood'))
                inst['bevindingen'] = [{
                    'severity': 'Info', 'categorie': 'Scanfout', 'pad': '',
                    'reden': 'Scan mislukt: %s' % e, 'bewijs': [],
                    'actie': 'Review', 'sha256': None, 'mtime': None}]
                inst.setdefault('bestanden', 0)
                inst.setdefault('hashkaart', {})
                inst.setdefault('geverifieerd', 0)

            t = tel_severity(inst.get('bevindingen', []))
            crit, hoog = t.get('Critical', 0), t.get('High', 0)
            regel = '%5d bestanden' % inst.get('bestanden', 0)
            if crit or hoog:
                # Apart tellen en apart kleuren: een site met 1 kritiek is een
                # ander gesprek dan een site met 22 hoog.
                delen = []
                if crit:
                    delen.append(c('%d kritiek' % crit, 'rood'))
                if hoog:
                    delen.append(c('%d hoog' % hoog, 'oranje'))
                print('%s  %s' % (regel, '  '.join(delen)))
            else:
                print(c('%s  schoon' % regel, 'groen'))
            alle_installaties.append(inst)

        extra = scan_user_extras(u['user'])
        if extra:
            # Hang ze aan de eerste installatie van deze user.
            u['installaties'][0]['bevindingen'].extend(extra)
            for b in extra:
                print('      %s %s'
                      % (c(b['severity'], sev_kleur(b['severity'])), b['reden']))

    # -- Sites onderling vergelijken ---------------------------------------
    print('')
    print('  Sites onderling vergelijken...')
    vergelijk_sites(alle_installaties)

    duur = int(time.time() - begin)

    # -- Rapporteren --------------------------------------------------------
    # Salts eerst klaarzetten: opruimen.sh verwijst er aan het eind naar.
    salt_pad, salt_n, salt_over = (None, 0, [])
    if not args.geen_salts:
        print('  Verse salts ophalen...')
        salt_pad, salt_n, salt_over = schrijf_saltscript(uitmap,
                                                         alle_installaties)

    # De gebruikersvraag staat bewust voor het schrijven van opruimen.sh: wat
    # je aanwijst komt daar als DEEL 6 in te staan.
    gebr_regels, gebr_n = [], 0
    if not args.yes and not args.geen_gebruikers and sys.stdin.isatty():
        kop('WORDPRESS-GEBRUIKERS')
        print('  Per site de accounts uit de database. Kijk vooral naar')
        print('  beheerders die je niet herkent.')
        print('  ' + c('Aanwijzen is nog niet verwijderen: het komt in '
                       'opruimen.sh te staan.', 'groen'))
        gebr_regels, gebr_n = kies_gebruikers(alle_installaties)

    # Het opruimscript merkt elke bevinding aan als wel of niet afgehandeld.
    # Daarom moet het VOOR het rapport draaien: dan staat in het rapport en in
    # de JSON meteen waar opruimen.sh wel en niet iets mee doet.
    op_pad, terug_pad, tel = schrijf_opruimscript(uitmap, alle_installaties,
                                                  salt_pad, salt_n,
                                                  gebr_regels, gebr_n)

    zelf = niet_gedaan(alle_installaties, server_bev)
    zelf_pad = schrijf_zelfdoen(uitmap, zelf) if zelf else None

    html = schrijf_html(uitmap, alle_installaties, server_bev,
                        len(te_scannen), duur)
    js = schrijf_json(uitmap, alle_installaties, server_bev)

    alle = []
    for inst in alle_installaties:
        alle.extend(inst.get('bevindingen', []))
    alle.extend(server_bev)
    tot = tel_severity(alle)

    kop('KLAAR')
    print('  Scanduur         %d min %d sec' % (duur // 60, duur % 60))
    print('  Installaties     %d' % len(alle_installaties))
    print('  Bestanden        %d' % sum(i.get('bestanden', 0)
                                        for i in alle_installaties))
    print('')
    for sev in ('Critical', 'High', 'Medium', 'Low', 'Info'):
        if tot.get(sev):
            print('  %-9s %s' % (sev, c(str(tot[sev]), sev_kleur(sev))))

    print('')
    print('  Rapport          %s' % c(html, 'vet'))
    print('  Ruwe data        %s' % js)
    print('')
    print('  ' + c('-' * 70, 'grijs'))
    print('  ' + c('KLAARGEZET IN OPRUIMEN.SH', 'vet'))
    print('  ' + c('-' * 70, 'grijs'))
    print('     %4d  naar quarantaine verplaatsen' % tel['Quarantine'])
    print('     %4d  terugzetten uit het officiele pakket'
          % tel['RestoreOfficial'])
    print('     %4d  repareren (alleen de kwade regels eruit)'
          % tel['FixInPlace'])
    if tel['OudThema']:
        print('     %4d  ongebruikt standaardthema opruimen' % tel['OudThema'])
    if tel['OudKern']:
        print('     %4d  verouderd kernbestand opruimen (restant van een '
              'update)' % tel['OudKern'])
    if gebr_n:
        print('     %4d  WordPress-account(en) verwijderen' % gebr_n)
    if salt_n:
        print('     %4d  site(s) verse salts geven (vraagt het script zelf)'
              % salt_n)
    print('')
    print('  ' + c('Er is nog niets gebeurd. Dat gebeurt pas als je '
                   'opruimen.sh draait.', 'groen'))
    print('')
    print('     nalezen        less %s' % op_pad)
    print('     uitvoeren      %s' % c('bash %s' % op_pad, 'vet'))
    print('     terugdraaien   bash %s' % terug_pad)
    print('  ' + c('-' * 70, 'grijs'))

    # Wat er NIET in het script staat is minstens zo belangrijk: dat blijft
    # anders ongemerkt liggen.
    if zelf:
        toon_zelfdoen(zelf, zelf_pad)
    else:
        print('')
        print('  ' + c('Elke Critical en High zit in opruimen.sh. Er blijft '
                       'niets liggen.', 'groen'))
    print('')

    if gebr_n or salt_n:
        print('  ' + c('Terugdraaien zet alleen de bestanden terug.', 'geel'))
        print('  Verwijderde accounts en nieuwe salts krijg je daar niet mee '
              'terug.')
        print('')
    if tel['geen_bron']:
        print('  %d bevinding(en) kon het script niet klaarzetten omdat er geen'
              % tel['geen_bron'])
        print('  schoon origineel voor is (premium plugin of maatwerkthema).')
        print('  Die staan in het rapport en moet je zelf bekijken.')
        print('')
    for domein, reden in salt_over:
        print('  ' + c('salts overgeslagen: %s -- %s' % (domein, reden), 'geel'))
    if salt_over:
        print('')

    print('  Wat het script NIET doet: de rest van de database. Geinjecteerde')
    print('  wp_options en verborgen code in berichten moet je zelf nakijken.')
    print('')

    # -- Wat is er nieuw sinds de vorige keer? ------------------------------
    nieuw_ernstig = 0
    if args.sinds or args.sinds_vorige:
        vorig = args.sinds or vorige_run(args.uit, stempel)
        oud = lees_sleutels(vorig) if vorig else None
        kop('NIEUW SINDS DE VORIGE RUN')
        if oud is None:
            print('  ' + c('Geen eerdere run om mee te vergelijken. Deze run '
                           'is nu je nulmeting.', 'geel'))
            print('')
        else:
            nieuw = [(inst['domein'], b)
                     for inst in alle_installaties
                     for b in inst.get('bevindingen', [])
                     if (inst['domein'], b['pad'], b['categorie']) not in oud]
            ernstig = [x for x in nieuw
                       if x[1]['severity'] in ('Critical', 'High')]
            nieuw_ernstig = len(ernstig)

            print('  Vergeleken met %s' % vorig)
            print('')
            if not nieuw:
                print('  ' + c('Niets nieuws.', 'groen'))
            else:
                for domein, b in sorted(
                        ernstig,
                        key=lambda x: (SEV_VOLGORDE[x[1]['severity']], x[0])):
                    print('  %s  %-26s %s'
                          % (c('%-8s' % b['severity'],
                               sev_kleur(b['severity'])),
                             domein[:26], b['pad'] or b['categorie']))
                rest = len(nieuw) - len(ernstig)
                if rest:
                    if ernstig:
                        print('')
                    print('  Plus %d nieuwe bevinding(en) op Medium of Info. '
                          'Die staan in' % rest)
                    print('  het rapport; het is context, geen alarm.')
            print('')

    # Exitcode 2 betekent: er is iets nieuws en ernstigs. Daar kun je in cron
    # of in je monitoring op reageren.
    return 2 if nieuw_ernstig else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print('')
        print('  Afgebroken.')
        sys.exit(130)
