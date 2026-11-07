"""helpers.py — Discord'a bağımlı olmayan saf mantık + SQLite katmanı."""
import difflib
import json
import re
import sqlite3
import time
import unicodedata
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

# ============================================================
#  AYAR ŞEMASI  (panel bu listeden otomatik oluşur)
# ============================================================
CATS = {
    "mesaj": "💬 Mesaj korumaları",
    "giris": "🚪 Giriş korumaları",
    "sunucu": "🏰 Sunucu korumaları",
    "ceza": "⚖️ Ceza",
    "log": "📜 Log ve rapor",
    "ai": "🤖 Yapay zeka",
}

SCHEMA = []


def _s(key, cat, label, kind, default, lo=None, hi=None, owner=False, unit=""):
    SCHEMA.append({"key": key, "cat": cat, "label": label, "kind": kind,
                   "default": default, "lo": lo, "hi": hi, "owner": owner, "unit": unit})


# --- mesaj ---
_s("antispam", "mesaj", "Anti-Spam (hız/tekrar)", "bool", True)
_s("spam_limit", "mesaj", "Spam: mesaj sayısı", "int", 5, 2, 20)
_s("spam_window", "mesaj", "Spam: süre", "int", 7, 2, 60, unit="sn")
_s("dup_limit", "mesaj", "Spam: aynı mesaj tekrarı", "int", 3, 2, 10)
_s("spam_timeout", "mesaj", "Spam cezası (timeout)", "int", 10, 1, 1440, unit="dk")
_s("coklukanal", "mesaj", "Çoklu kanal spam'i", "bool", True)
_s("kufur", "mesaj", "Küfür filtresi", "bool", True)
_s("link", "mesaj", "Link/davet filtresi", "bool", True)
_s("phishing", "mesaj", "Kimlik avı linki kontrolü", "bool", True)
_s("mention", "mesaj", "Toplu etiket", "bool", True)
_s("mention_limit", "mesaj", "Toplu etiket: en çok etiket", "int", 5, 2, 20)
_s("caps", "mesaj", "Büyük harf spam'i", "bool", True)
_s("caps_min", "mesaj", "Büyük harf: en az harf sayısı", "int", 12, 5, 100)
_s("caps_oran", "mesaj", "Büyük harf: oran", "int", 70, 50, 100, unit="%")
_s("emoji", "mesaj", "Emoji spam'i", "bool", True)
_s("emoji_limit", "mesaj", "Emoji: en çok emoji", "int", 10, 3, 50)
_s("zalgo", "mesaj", "Görünmez/zalgo karakter + uzun mesaj", "bool", True)
_s("maks_uzunluk", "mesaj", "Maksimum mesaj uzunluğu", "int", 1500, 200, 4000, unit="karakter")
_s("dosya", "mesaj", "Tehlikeli dosya uzantıları", "bool", True)
_s("ghost", "mesaj", "Ghost ping tespiti", "bool", True)
# --- giriş ---
_s("antiraid", "giris", "Anti-Raid", "bool", True)
_s("raid_limit", "giris", "Raid: kişi sayısı", "int", 4, 2, 30)
_s("raid_window", "giris", "Raid: süre", "int", 10, 3, 120, unit="sn")
_s("raid_lockdown", "giris", "Raid: lockdown süresi", "int", 120, 30, 3600, unit="sn")
_s("raid_yavas", "giris", "Raid'de otomatik yavaş mod", "bool", True)
_s("raid_yavas_sn", "giris", "Raid yavaş mod süresi", "int", 10, 1, 120, unit="sn")
_s("hesapyasi", "giris", "Yeni hesap filtresi", "bool", True)
_s("hesap_gun", "giris", "Yeni hesap: en az yaş", "int", 7, 1, 90, unit="gün")
_s("botkoruma", "giris", "Bot ekleme koruması (sadece sahip ekler)", "bool", True, owner=True)
_s("taklit", "giris", "Yetkili taklit koruması", "bool", True)
_s("taklit_oran", "giris", "Taklit: isim benzerlik eşiği", "int", 85, 70, 100, unit="%")
_s("taklit_at", "giris", "Birebir taklitçiyi otomatik at", "bool", False)
# --- sunucu ---
_s("antinuke", "sunucu", "Anti-Nuke", "bool", True, owner=True)
_s("nuke_sil_limit", "sunucu", "Nuke: kanal/rol silme limiti", "int", 2, 1, 10, owner=True)
_s("nuke_ban_limit", "sunucu", "Nuke: ban/kick limiti", "int", 4, 2, 20, owner=True)
_s("nuke_olustur_limit", "sunucu", "Nuke: kanal/rol oluşturma limiti", "int", 4, 2, 20, owner=True)
_s("nuke_pencere", "sunucu", "Nuke: süre penceresi", "int", 10, 5, 60, owner=True, unit="sn")
_s("yetkikoruma", "sunucu", "Yetki koruması", "bool", True, owner=True)
_s("sunucukoruma", "sunucu", "Sunucu ayarı koruması (ad/ikon)", "bool", True, owner=True)
_s("webhook", "sunucu", "Webhook koruması", "bool", True, owner=True)
_s("ses", "sunucu", "Ses kanalı spam'i", "bool", True)
_s("ses_limit", "sunucu", "Ses spam: giriş sayısı", "int", 5, 3, 20)
_s("ses_pencere", "sunucu", "Ses spam: süre", "int", 20, 5, 120, unit="sn")
# --- ceza ---
_s("mute_gun", "ceza", "Uyarı basamağı: mute süresi", "int", 1, 1, 28, unit="gün")
_s("uyari_omur", "ceza", "Uyarı geçerlilik süresi (0 = silinmez)", "int", 0, 0, 365, unit="gün")
# --- log ---
_s("log_olay", "log", "Olay logu (audit, giriş/çıkış, profil)", "bool", True)
_s("log_mesaj", "log", "Mesaj silme/düzenleme logu", "bool", True)
_s("log_ses", "log", "Ses kanalı logu", "bool", True)
_s("log_tepki", "log", "Tepki logu (kalabalık yapar)", "bool", False)
_s("mesaj_cache_saat", "log", "Geçici mesaj yedeği süresi (0 = kapalı)", "int", 48, 0, 168, unit="saat")
_s("gorsel_cache", "log", "Görselleri geçici sakla", "bool", True)
_s("rapor", "log", "Günlük güvenlik raporu", "bool", True)
_s("rapor_saat", "log", "Rapor saati", "int", 9, 0, 23, unit=":00")
_s("tz", "log", "Saat dilimi (UTC farkı)", "int", 3, -12, 14, unit="saat")

# --- yapay zeka ---
_s("ai", "ai", "Yapay zeka açık", "bool", True, owner=True)
_s("ai_arac", "ai", "AI işlem yapabilsin (kapalıysa sadece sohbet)", "bool", True, owner=True)
_s("ai_gunluk_limit", "ai", "AI: günlük istek limiti (maliyet koruması)", "int", 200, 1, 5000, owner=True)
_s("ai_dk_limit", "ai", "AI: kişi başı dakikada istek", "int", 6, 1, 30, owner=True)

SCHEMA_BY_KEY = {s["key"]: s for s in SCHEMA}
DEFAULTS = {s["key"]: s["default"] for s in SCHEMA}


# ============================================================
#  SÜRE
# ============================================================
SURE_RE = re.compile(r"(\d+)\s*(sn|dk|sa|gün|g|s|m|h|d)", re.I)
SURE_BIRIM = {"sn": 1, "s": 1, "dk": 60, "m": 60, "sa": 3600, "h": 3600,
              "g": 86400, "gün": 86400, "d": 86400}


def parse_sure(text):
    """(geçerli_mi, saniye) döner. Süresiz için saniye None."""
    t = text.strip().lower()
    if t in ("suresiz", "süresiz", "0"):
        return True, None
    parts = SURE_RE.findall(t)
    if not parts or SURE_RE.sub("", t).strip():
        return False, None
    total = sum(int(n) * SURE_BIRIM[u] for n, u in parts)
    if total <= 0:
        return False, None
    return True, min(total, 365 * 86400)


def fmt_sure(sec):
    if sec is None:
        return "süresiz"
    sec = int(sec)
    parts = []
    for ad, b in (("gün", 86400), ("saat", 3600), ("dk", 60)):
        n, sec = divmod(sec, b)
        if n:
            parts.append(f"{n} {ad}")
    return " ".join(parts) or f"{sec} sn"


def day_key(ts, tz_hours=3):
    tz = timezone(timedelta(hours=tz_hours))
    return datetime.fromtimestamp(ts, tz).strftime("%Y-%m-%d")


def short(v, n=80):
    return str(v)[:n]


# ============================================================
#  METİN FİLTRELERİ
# ============================================================
LEET = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "i", "!": "i",
                      "0": "o", "$": "s", "5": "s"})


def normalize(text):
    return text.replace("İ", "i").lower().translate(LEET)


def match_word(norm_text, word, mode="tam"):
    w = normalize(word).strip()
    if not w:
        return False
    if mode == "icinde":
        return w in norm_text
    return re.search(r"(?<!\w)" + re.escape(w) + r"(?!\w)", norm_text) is not None


def caps_info(text):
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0, 0.0
    up = sum(1 for c in letters if c.isupper())
    return len(letters), up / len(letters)


EMOJI_RE = re.compile(
    r"<a?:\w{2,32}:\d{17,20}>|[\U0001F300-\U0001FAFF\u2600-\u27BF\U0001F1E6-\U0001F1FF\u2B50]")


def emoji_count(text):
    return len(EMOJI_RE.findall(text))


def invisible_count(text):
    return sum(1 for c in text if unicodedata.category(c) == "Cf")


def zalgo_count(text):
    return sum(1 for c in text if unicodedata.category(c) in ("Mn", "Me"))


# ============================================================
#  LİNKLER
# ============================================================
URL_RE = re.compile(
    r"(?:https?://|www\.)[^\s<>]+|discord(?:app)?\.(?:gg|com/invite)/[^\s<>]+", re.I)


def extract_urls(text):
    return URL_RE.findall(text)


def host_of(url):
    low = url.lower()
    u = low if low.startswith("http") else "http://" + low
    try:
        host = urlparse(u).hostname or ""
    except ValueError:
        return ""
    return host[4:] if host.startswith("www.") else host


def is_invite(url):
    low = url.lower()
    return "discord.gg/" in low or ("/invite/" in low and "discord" in low)


def host_allowed(host, allowed):
    return any(host == d or host.endswith("." + d) for d in allowed)


def blocked_link(text, allowed):
    """Engellenmesi gereken ilk linki döndürür (yoksa None). Davetler hep engelli."""
    for u in extract_urls(text):
        if is_invite(u):
            return u
        if not host_allowed(host_of(u), allowed):
            return u
    return None


OFFICIAL = ("discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media",
            "discord.gift", "discordstatus.com", "discord.new", "discord.dev",
            "steamcommunity.com", "steampowered.com")
SQUAT_TARGETS = ("discord", "discordapp", "steamcommunity", "steampowered")
PHISH_WORDS = ("discord", "nitro", "steamcommunity", "steampowered")


def is_phishing(host, allowed=()):
    if not host:
        return False
    if host_allowed(host, OFFICIAL) or host_allowed(host, allowed):
        return False
    if host.startswith("xn--") or ".xn--" in host:
        return True
    flat = host.replace("-", "").replace(".", "")
    if any(w in flat for w in PHISH_WORDS):
        return True
    labels = host.split(".")
    sld = labels[-2] if len(labels) >= 2 else labels[0]
    return any(sld != t and difflib.SequenceMatcher(None, sld, t).ratio() >= 0.8
               for t in SQUAT_TARGETS)


# ============================================================
#  İSİM BENZERLİĞİ (taklit koruması)
# ============================================================
HOMO = str.maketrans({
    "0": "o", "1": "i", "l": "i", "|": "i", "!": "i", "3": "e", "4": "a", "5": "s",
    "7": "t", "@": "a", "$": "s", "ı": "i", "İ": "i", "ş": "s", "ğ": "g", "ü": "u",
    "ö": "o", "ç": "c",
    "і": "i", "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
})


def norm_name(s):
    s = unicodedata.normalize("NFKD", s.lower())
    s = "".join(c for c in s if not unicodedata.combining(c)).translate(HOMO)
    return "".join(c for c in s if c.isalnum())


def name_similarity(a, b):
    na, nb = norm_name(a), norm_name(b)
    if min(len(na), len(nb)) < 3:
        return 0.0
    if na == nb:
        return 1.0
    return difflib.SequenceMatcher(None, na, nb).ratio()


# ============================================================
#  UYARI BASAMAKLARI:  uyarı, uyarı, 1 gün mute, kick, ban
# ============================================================
def warn_action(n):
    if n <= 2:
        return "uyari"
    if n == 3:
        return "mute"
    if n == 4:
        return "kick"
    return "ban"


# ============================================================
#  VERİTABANI
# ============================================================
SQL_INIT = """
CREATE TABLE IF NOT EXISTS guild_config (guild_id INTEGER PRIMARY KEY, data TEXT);
CREATE TABLE IF NOT EXISTS warnings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id INTEGER, user_id INTEGER,
    mod_id INTEGER, reason TEXT, ts REAL);
CREATE INDEX IF NOT EXISTS ix_warn ON warnings(guild_id, user_id);
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT, guild_id INTEGER, user_id INTEGER,
    author_id INTEGER, text TEXT, ts REAL);
CREATE INDEX IF NOT EXISTS ix_notes ON notes(guild_id, user_id);
CREATE TABLE IF NOT EXISTS blacklist (
    guild_id INTEGER, user_id INTEGER, reason TEXT, ts REAL,
    PRIMARY KEY (guild_id, user_id));
CREATE TABLE IF NOT EXISTS words (
    guild_id INTEGER, word TEXT, mode TEXT, PRIMARY KEY (guild_id, word));
CREATE TABLE IF NOT EXISTS domains (
    guild_id INTEGER, domain TEXT, PRIMARY KEY (guild_id, domain));
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY, guild_id INTEGER, channel_id INTEGER, author_id INTEGER,
    author_name TEXT, content TEXT, mentions TEXT, files TEXT, ts REAL);
CREATE INDEX IF NOT EXISTS ix_msg ON messages(guild_id, ts);
CREATE TABLE IF NOT EXISTS stats (
    guild_id INTEGER, day TEXT, key TEXT, n INTEGER,
    PRIMARY KEY (guild_id, day, key));
CREATE TABLE IF NOT EXISTS tempbans (
    guild_id INTEGER, user_id INTEGER, until REAL, PRIMARY KEY (guild_id, user_id));
CREATE TABLE IF NOT EXISTS kv (
    guild_id INTEGER, key TEXT, value TEXT, PRIMARY KEY (guild_id, key));
"""


class DB:
    def __init__(self, path="guard.db"):
        self.con = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.con.row_factory = sqlite3.Row
        self.con.execute("PRAGMA journal_mode=WAL")
        self.con.executescript(SQL_INIT)
        self._words = {}
        self._domains = {}

    def x(self, sql, args=()):
        return self.con.execute(sql, args)

    def rows(self, sql, args=()):
        return self.con.execute(sql, args).fetchall()

    def row(self, sql, args=()):
        return self.con.execute(sql, args).fetchone()

    # ---- sunucu ayarları ----
    def load_config(self):
        return {str(r["guild_id"]): json.loads(r["data"])
                for r in self.rows("SELECT guild_id, data FROM guild_config")}

    def save_config(self, guild_id, data):
        self.x("INSERT OR REPLACE INTO guild_config VALUES (?, ?)",
               (guild_id, json.dumps(data, ensure_ascii=False)))

    # ---- uyarılar ----
    def warn_add(self, guild_id, user_id, mod_id, reason):
        cur = self.x("INSERT INTO warnings (guild_id, user_id, mod_id, reason, ts) "
                     "VALUES (?, ?, ?, ?, ?)", (guild_id, user_id, mod_id, reason, time.time()))
        return cur.lastrowid

    def warn_list(self, guild_id, user_id, omur_gun=0):
        if omur_gun and omur_gun > 0:
            cutoff = time.time() - omur_gun * 86400
            return self.rows("SELECT * FROM warnings WHERE guild_id=? AND user_id=? AND ts>=? "
                             "ORDER BY id", (guild_id, user_id, cutoff))
        return self.rows("SELECT * FROM warnings WHERE guild_id=? AND user_id=? ORDER BY id",
                         (guild_id, user_id))

    def warn_del(self, guild_id, warn_id):
        return self.x("DELETE FROM warnings WHERE guild_id=? AND id=?",
                      (guild_id, warn_id)).rowcount > 0

    # ---- yetkili notları ----
    def note_add(self, guild_id, user_id, author_id, text):
        cur = self.x("INSERT INTO notes (guild_id, user_id, author_id, text, ts) "
                     "VALUES (?, ?, ?, ?, ?)", (guild_id, user_id, author_id, text, time.time()))
        return cur.lastrowid

    def note_list(self, guild_id, user_id):
        return self.rows("SELECT * FROM notes WHERE guild_id=? AND user_id=? ORDER BY id",
                         (guild_id, user_id))

    def note_del(self, guild_id, note_id):
        return self.x("DELETE FROM notes WHERE guild_id=? AND id=?",
                      (guild_id, note_id)).rowcount > 0

    # ---- kara liste ----
    def bl_add(self, guild_id, user_id, reason):
        self.x("INSERT OR REPLACE INTO blacklist VALUES (?, ?, ?, ?)",
               (guild_id, user_id, reason, time.time()))

    def bl_del(self, guild_id, user_id):
        return self.x("DELETE FROM blacklist WHERE guild_id=? AND user_id=?",
                      (guild_id, user_id)).rowcount > 0

    def bl_has(self, guild_id, user_id):
        return self.row("SELECT 1 FROM blacklist WHERE guild_id=? AND user_id=?",
                        (guild_id, user_id)) is not None

    def bl_list(self, guild_id):
        return self.rows("SELECT * FROM blacklist WHERE guild_id=? ORDER BY ts", (guild_id,))

    # ---- yasaklı kelimeler / izinli domainler (bellekte önbellekli) ----
    def words(self, guild_id):
        if guild_id not in self._words:
            self._words[guild_id] = [(r["word"], r["mode"]) for r in self.rows(
                "SELECT word, mode FROM words WHERE guild_id=?", (guild_id,))]
        return self._words[guild_id]

    def word_add(self, guild_id, word, mode):
        self.x("INSERT OR REPLACE INTO words VALUES (?, ?, ?)", (guild_id, word, mode))
        self._words.pop(guild_id, None)

    def word_del(self, guild_id, word):
        ok = self.x("DELETE FROM words WHERE guild_id=? AND word=?",
                    (guild_id, word)).rowcount > 0
        self._words.pop(guild_id, None)
        return ok

    def domains(self, guild_id):
        if guild_id not in self._domains:
            self._domains[guild_id] = [r["domain"] for r in self.rows(
                "SELECT domain FROM domains WHERE guild_id=?", (guild_id,))]
        return self._domains[guild_id]

    def domain_add(self, guild_id, domain):
        self.x("INSERT OR IGNORE INTO domains VALUES (?, ?)", (guild_id, domain))
        self._domains.pop(guild_id, None)

    def domain_del(self, guild_id, domain):
        ok = self.x("DELETE FROM domains WHERE guild_id=? AND domain=?",
                    (guild_id, domain)).rowcount > 0
        self._domains.pop(guild_id, None)
        return ok

    # ---- geçici mesaj yedeği ----
    def msg_add(self, mid, guild_id, channel_id, author_id, author_name, content, mentions, files):
        self.x("INSERT OR REPLACE INTO messages VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
               (mid, guild_id, channel_id, author_id, author_name, content,
                json.dumps(mentions), json.dumps(files), time.time()))

    def msg_get(self, mid):
        return self.row("SELECT * FROM messages WHERE id=?", (mid,))

    def msg_update(self, mid, content):
        self.x("UPDATE messages SET content=? WHERE id=?", (content, mid))

    def msg_del(self, mid):
        self.x("DELETE FROM messages WHERE id=?", (mid,))

    def msg_purge(self, guild_id, cutoff):
        """cutoff'tan eski kayıtları siler, silinecek dosya yollarını döndürür."""
        paths = []
        for r in self.rows("SELECT files FROM messages WHERE guild_id=? AND ts<?",
                           (guild_id, cutoff)):
            try:
                paths += json.loads(r["files"]).get("p", [])
            except (ValueError, AttributeError):
                pass
        self.x("DELETE FROM messages WHERE guild_id=? AND ts<?", (guild_id, cutoff))
        return paths

    # ---- istatistik ----
    def stat_inc(self, guild_id, day, key, n=1):
        self.x("INSERT INTO stats VALUES (?, ?, ?, ?) "
               "ON CONFLICT(guild_id, day, key) DO UPDATE SET n = n + excluded.n",
               (guild_id, day, key, n))

    def stat_day(self, guild_id, day):
        return {r["key"]: r["n"] for r in self.rows(
            "SELECT key, n FROM stats WHERE guild_id=? AND day=?", (guild_id, day))}

    # ---- süreli ban ----
    def tb_add(self, guild_id, user_id, until):
        self.x("INSERT OR REPLACE INTO tempbans VALUES (?, ?, ?)", (guild_id, user_id, until))

    def tb_due(self, now):
        return self.rows("SELECT * FROM tempbans WHERE until<=?", (now,))

    def tb_del(self, guild_id, user_id):
        self.x("DELETE FROM tempbans WHERE guild_id=? AND user_id=?", (guild_id, user_id))

    # ---- genel anahtar/değer ----
    def kv_get(self, guild_id, key):
        r = self.row("SELECT value FROM kv WHERE guild_id=? AND key=?", (guild_id, key))
        return json.loads(r["value"]) if r else None

    def kv_set(self, guild_id, key, value):
        self.x("INSERT OR REPLACE INTO kv VALUES (?, ?, ?)", (guild_id, key, json.dumps(value)))

    def kv_del(self, guild_id, key):
        self.x("DELETE FROM kv WHERE guild_id=? AND key=?", (guild_id, key))
