"""Генерация тестовых фикстур .kdbx сторонней реализацией (pykeepass).

Смысл: наши Rust-тесты исторически проверяли только round-trip собственной
реализации — если она симметрично «неправильная», тесты остаются зелёными, а
файл не открывается ни в одном настоящем KeePass. Эти фикстуры собраны чужим
кодом, поэтому служат внешним эталоном формата KDBX4.

Фикстуры коммитятся в git (tests/resources), Rust-тесты читают готовые файлы —
Python не нужен для `cargo test`. Запускать только при осознанной перегенерации.

Использование (из корня pass-rust-core):
    .venv/Scripts/python.exe tools/kdbx-oracle/gen_fixtures.py
"""

import base64
import hashlib
import os
import shutil
import sys
import uuid as uuid_mod
from datetime import datetime, timezone

if hasattr(sys.stdout, "reconfigure"):
    # Windows-консоль не utf-8 по умолчанию
    sys.stdout.reconfigure(encoding="utf-8")
from pathlib import Path

from lxml.etree import SubElement
from pykeepass import PyKeePass, create_database
from pykeepass.kdbx_parsing.kdbx4 import kdf_uuids

REPO_ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = REPO_ROOT / "tests" / "resources"

# Пароль фейковый и одинаковый для всех фикстур: файлы лежат в git, секретов в них нет.
PASSWORD = "test-pass-1234"

# Заниженные параметры Argon2: каждый Rust-тест платит за KDF при открытии базы,
# на боевых 64 MB / 10 iter прогон тестов становится ощутимо медленнее.
FAST_ARGON2 = {"memory_mb": 16, "iterations": 2, "parallelism": 2}
# Одна фикстура с боевыми параметрами — проверяем, что и такие читаются.
PROD_ARGON2 = {"memory_mb": 64, "iterations": 10, "parallelism": 2}

IV_LENGTHS = {"aes256": 16, "chacha20": 12, "twofish": 16}

ATTACHMENT_NAME = "notes.txt"
ATTACHMENT_DATA = b"example doc\n2 lines\n"
TOTP_URL = "otpauth://totp/server?secret=JBSWY3DPEHPK3PXP&issuer=demo&algorithm=SHA1&digits=6&period=30"

FIXTURES = [
    # (имя файла, шифр, kdf, параметры argon2, использовать key-file)
    ("aes256_argon2d.kdbx", "aes256", "argon2", FAST_ARGON2, False),
    ("chacha20_argon2id.kdbx", "chacha20", "argon2id", FAST_ARGON2, False),
    ("aes256_argon2d_keyfile.kdbx", "aes256", "argon2", FAST_ARGON2, True),
    ("aes256_argon2d_prod_params.kdbx", "aes256", "argon2", PROD_ARGON2, False),
]


# --- Фикстура сохранности данных (Step 13) -----------------------------------
#
# Step 13 удаляет из ядра КОД passkey / SFTP-WebDAV / AutoOpen, но НЕ формат:
# записи таких типов, созданные OneKeePass или KeePassXC, должны и дальше
# читаться и сохраняться без потерь. Эта фикстура собрана чужой реализацией и
# содержит ровно то, что удаление могло бы незаметно испортить.
#
# Тип записи OneKeePass хранится в CustomData самой записи: ключ OKP_K3,
# значение — base64 от 16 байт uuid типа (src/constants.rs, util::encode_uuid).
# pykeepass не умеет CustomData, поэтому элемент добавляется через lxml.
PRESERVATION_FIXTURE = "okp_entry_types.kdbx"

CUSTOM_DATA_KEY_ENTRY_TYPE = "OKP_K3"

ENTRY_TYPE_UUIDS = {
    "auto_db_open": "389368a9-73a9-4256-8247-321a2e60b2c7",
    "sftp": "c5a57a41-4cca-4a46-bac1-78a8803f4da0",
    "webdav": "0a14d76d-8c38-4c62-9ad7-390dc020a2af",
}

# Поля passkey в формате KeePassXC (constants.rs, entry_type_name::KPEX_*).
PASSKEY_FIELDS = {
    "KPEX_PASSKEY_USERNAME": "octocat",
    "KPEX_PASSKEY_RELYING_PARTY": "github.com",
    "KPEX_PASSKEY_USER_HANDLE": "dXNlci1oYW5kbGUtMQ",
    "KPEX_PASSKEY_CREDENTIAL_ID": "Y3JlZC1pZC0x",
}
# Однострочный фейковый ключ: содержимое неважно, важно что поле protected
# и переживает сохранение нашим ядром.
PASSKEY_PRIVATE_KEY = "fake-pkcs8-private-key-for-tests"


def set_entry_type(entry, type_key):
    """Проставить записи тип OneKeePass через CustomData/Item (OKP_K3)."""
    raw = uuid_mod.UUID(ENTRY_TYPE_UUIDS[type_key]).bytes
    custom_data = SubElement(entry._element, "CustomData")
    item = SubElement(custom_data, "Item")
    SubElement(item, "Key").text = CUSTOM_DATA_KEY_ENTRY_TYPE
    SubElement(item, "Value").text = base64.b64encode(raw).decode("ascii")


def fill_preservation_content(kp):
    root = kp.root_group

    # 1. Passkey: обычная Login-запись с полями KeePassXC. Приватный ключ protected.
    passkey = kp.add_entry(root, "Passkey Site", "octocat", "pk-secret-1",
                           url="https://github.com")
    for key, value in PASSKEY_FIELDS.items():
        passkey.set_custom_property(key, value)
    passkey.set_custom_property("KPEX_PASSKEY_PRIVATE_KEY_PEM", PASSKEY_PRIVATE_KEY,
                                protect=True)

    # 2. AutoOpen: группа с записью типа "Auto Database Open".
    auto_open = kp.add_group(root, "AutoOpen")
    auto_entry = kp.add_entry(auto_open, "Work DB", "dbuser", "db-secret-2",
                              url="kdbx://work.kdbx")
    auto_entry.set_custom_property("IfDevice", "laptop")
    set_entry_type(auto_entry, "auto_db_open")

    # 3. SFTP / WebDAV: записи типов удалённых подключений OneKeePass.
    connections = kp.add_group(root, "Connections")

    sftp = kp.add_entry(connections, "My SFTP", "sftpuser", "sftp-secret-3")
    sftp.set_custom_property("Host", "sftp.example.com")
    sftp.set_custom_property("Port", "22")
    sftp.set_custom_property("Start Dir", "/home/sftpuser")
    set_entry_type(sftp, "sftp")

    webdav = kp.add_entry(connections, "My WebDAV", "davuser", "dav-secret-4",
                          url="https://dav.example.com/remote.php/dav")
    webdav.set_custom_property("Allow Untrusted Cert", "true")
    set_entry_type(webdav, "webdav")


def verify_preservation(db_path):
    kp = PyKeePass(str(db_path), password=PASSWORD)

    assert sorted(g.name for g in kp.groups) == ["AutoOpen", "Connections", "Root"]
    assert sorted(e.title for e in kp.entries) == [
        "My SFTP", "My WebDAV", "Passkey Site", "Work DB",
    ]

    passkey = kp.find_entries(title="Passkey Site", first=True)
    for key, value in PASSKEY_FIELDS.items():
        assert passkey.get_custom_property(key) == value, key
    assert passkey.get_custom_property("KPEX_PASSKEY_PRIVATE_KEY_PEM") == PASSKEY_PRIVATE_KEY

    for title, type_key in (("Work DB", "auto_db_open"), ("My SFTP", "sftp"),
                            ("My WebDAV", "webdav")):
        entry = kp.find_entries(title=title, first=True)
        items = entry._element.findall("CustomData/Item")
        stored = {i.find("Key").text: i.find("Value").text for i in items}
        expected = base64.b64encode(uuid_mod.UUID(ENTRY_TYPE_UUIDS[type_key]).bytes).decode("ascii")
        assert stored.get(CUSTOM_DATA_KEY_ENTRY_TYPE) == expected, (title, stored)


def build_preservation_fixture():
    db_path = OUT_DIR / PRESERVATION_FIXTURE
    if db_path.exists():
        db_path.unlink()

    kp = create_database(str(db_path), password=PASSWORD)

    header = kp.kdbx.header.value.dynamic_header
    header.cipher_id.data = "aes256"
    header.encryption_iv.data = os.urandom(IV_LENGTHS["aes256"])
    params = header.kdf_parameters.data.dict
    params["$UUID"].value = kdf_uuids["argon2id"]
    params["M"].value = FAST_ARGON2["memory_mb"] * 1024 * 1024
    params["I"].value = FAST_ARGON2["iterations"]
    params["P"].value = FAST_ARGON2["parallelism"]

    fill_preservation_content(kp)
    kp.save()
    verify_preservation(db_path)
    return db_path


# --- Фикстура «все поля KDBX 4.1» (Step 17) ------------------------------------
#
# Приложение работает в первую очередь с чужими базами. Всё, что ядро при
# сохранении теряет или меняет, пользователь увидит только в другом клиенте.
# Здесь КАЖДЫЙ элемент KDBX 4.1 у Meta, групп, записей, истории и DeletedObjects
# заполнен не значением по умолчанию — потеря или сброс видны при сравнении
# до / после (compare_roundtrip.py) и в tests/data_preservation.rs.
#
# Список элементов — KeePassLib (KdbxFile.Write) и KeePassXC (KdbxXmlWriter.cpp).
# pykeepass выставляет в API малую часть, остальное пишется через lxml напрямую.
# Значения продублированы константами в tests/data_preservation.rs — менять вместе.
ALL_FIELDS_FIXTURE = "all_fields_41.kdbx"

# Детерминированные UUID: тесты ищут объекты по ним.
AF_UUIDS = {
    "work": "5a0e3a4e-0000-4000-8000-000000000001",
    "templates": "5a0e3a4e-0000-4000-8000-000000000002",
    "recycle_bin": "5a0e3a4e-0000-4000-8000-000000000003",
    "entry": "5a0e3a4e-0000-4000-8000-000000000010",
    "icon": "5a0e3a4e-0000-4000-8000-000000000020",
    "deleted": "5a0e3a4e-0000-4000-8000-000000000030",
}

# Прозрачный PNG 1x1 — содержимое иконки ядро не разбирает, только хранит.
AF_ICON_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
)

# Элемент, которого нет в KDBX 4.1: проверка сырого хранения неизвестного (Meta, группа, запись).
AF_UNKNOWN_TAG = "XPassholderUnknown"
AF_UNKNOWN_ATTR = ("Origin", "fixture")
AF_UNKNOWN_CHILD = ("Inner", "unknown-value")
# Protected-значение внутри неизвестного элемента записи. Inner stream расшифровывает
# protected-значения по порядку документа: если ядро пропустит это значение, не
# расшифровав, все следующие (пароль в истории) расшифруются мусором.
AF_UNKNOWN_SECRET = "unknown-secret"


def b64_uuid(key):
    return base64.b64encode(uuid_mod.UUID(AF_UUIDS[key]).bytes).decode("ascii")


def af_time(kp, day):
    """Разные даты для разных полей — перепутанное поле тоже будет видно."""
    return kp._encode_time(datetime(2021, 3, day, 10, 20, 30, tzinfo=timezone.utc))


def put(parent, tag, text):
    """Задать значение дочернего элемента: заменить существующее или вставить новое.

    Новое вставляется перед первым вложенным Entry / Group / History — так же, как
    раскладывают элементы KeePass и KeePassXC (свои поля объекта идут до детей).
    """
    el = parent.find(tag)
    if el is None:
        el = parent.makeelement(tag, {})
        anchor = next((c for c in parent if c.tag in ("Entry", "Group", "History")), None)
        if anchor is None:
            parent.append(el)
        else:
            anchor.addprevious(el)
    el.text = text
    return el


def put_times(kp, obj_el, first_day):
    times = obj_el.find("Times")
    put(times, "CreationTime", af_time(kp, first_day))
    put(times, "LastModificationTime", af_time(kp, first_day + 1))
    put(times, "LastAccessTime", af_time(kp, first_day + 2))
    put(times, "ExpiryTime", af_time(kp, first_day + 3))
    put(times, "Expires", "True")
    put(times, "UsageCount", "5")
    put(times, "LocationChanged", af_time(kp, first_day + 4))


def put_custom_data(kp, obj_el, key, value, day):
    custom_data = obj_el.find("CustomData")
    if custom_data is None:
        custom_data = put(obj_el, "CustomData", None)
    item = SubElement(custom_data, "Item")
    SubElement(item, "Key").text = key
    SubElement(item, "Value").text = value
    SubElement(item, "LastModificationTime").text = af_time(kp, day)


def put_unknown(obj_el, with_secret=False):
    unknown = put(obj_el, AF_UNKNOWN_TAG, None)
    unknown.set(*AF_UNKNOWN_ATTR)
    SubElement(unknown, AF_UNKNOWN_CHILD[0]).text = AF_UNKNOWN_CHILD[1]
    if with_secret:
        # pykeepass шифрует при сохранении любой Value[@Protected='True']
        secret = SubElement(unknown, "Value", Protected="True")
        secret.text = AF_UNKNOWN_SECRET


def fill_all_fields_meta(kp):
    meta = kp.tree.getroot().find("Meta")
    # "&" and "<": text must not gain "&amp;" on every save
    put(meta, "DatabaseName", "All Fields & <4.1>")
    put(meta, "DatabaseNameChanged", af_time(kp, 1))
    put(meta, "DatabaseDescription", "every KDBX 4.1 element, non-default")
    put(meta, "DatabaseDescriptionChanged", af_time(kp, 2))
    put(meta, "DefaultUserName", "default-user")
    put(meta, "DefaultUserNameChanged", af_time(kp, 3))
    put(meta, "MaintenanceHistoryDays", "123")
    put(meta, "Color", "#FF8800")
    put(meta, "MasterKeyChanged", af_time(kp, 4))
    put(meta, "MasterKeyChangeRec", "90")
    put(meta, "MasterKeyChangeForce", "180")
    put(meta, "MasterKeyChangeForceOnce", "True")

    protection = meta.find("MemoryProtection")
    if protection is None:
        protection = put(meta, "MemoryProtection", None)
    # По умолчанию в KeePass защищён только пароль. Здесь всё наоборот.
    put(protection, "ProtectTitle", "True")
    put(protection, "ProtectUserName", "True")
    put(protection, "ProtectPassword", "False")
    put(protection, "ProtectURL", "True")
    put(protection, "ProtectNotes", "True")

    icons = meta.find("CustomIcons")
    if icons is None:
        icons = put(meta, "CustomIcons", None)
    icon = SubElement(icons, "Icon")
    SubElement(icon, "UUID").text = b64_uuid("icon")
    SubElement(icon, "Data").text = base64.b64encode(AF_ICON_PNG).decode("ascii")
    SubElement(icon, "Name").text = "fixture-icon"
    SubElement(icon, "LastModificationTime").text = af_time(kp, 5)

    put(meta, "RecycleBinEnabled", "False")
    put(meta, "RecycleBinUUID", b64_uuid("recycle_bin"))
    put(meta, "RecycleBinChanged", af_time(kp, 6))
    put(meta, "EntryTemplatesGroup", b64_uuid("templates"))
    put(meta, "EntryTemplatesGroupChanged", af_time(kp, 7))
    put(meta, "HistoryMaxItems", "7")
    put(meta, "HistoryMaxSize", str(3 * 1024 * 1024))
    put(meta, "LastSelectedGroup", b64_uuid("work"))
    put(meta, "LastTopVisibleGroup", b64_uuid("templates"))
    put(meta, "SettingsChanged", af_time(kp, 8))
    put_custom_data(kp, meta, "X-Meta-Key", "meta-value", 9)
    put_unknown(meta)


def set_uuid(obj, key):
    obj._element.find("UUID").text = b64_uuid(key)


def fill_all_fields_groups(kp):
    root = kp.root_group
    # Трёхзначные флаги (null / True / False): корень — True, Work — False, корзина — null.
    put(root._element, "Notes", "root notes")
    put(root._element, "EnableAutoType", "True")
    put(root._element, "EnableSearching", "True")
    put(root._element, "DefaultAutoTypeSequence", "{USERNAME}{TAB}{PASSWORD}")

    templates = kp.add_group(root, "Templates")
    set_uuid(templates, "templates")
    bin_group = kp.add_group(root, "Recycle Bin")
    set_uuid(bin_group, "recycle_bin")
    put(bin_group._element, "IconID", "43")
    put(bin_group._element, "EnableAutoType", "null")
    put(bin_group._element, "EnableSearching", "null")

    work = kp.add_group(root, "Work & Co")
    set_uuid(work, "work")
    el = work._element
    put(el, "Notes", "work group notes")
    put(el, "IconID", "48")
    put(el, "CustomIconUUID", b64_uuid("icon"))
    put_times(kp, el, 10)
    put(el, "IsExpanded", "False")
    put(el, "DefaultAutoTypeSequence", "{USERNAME}{ENTER}")
    put(el, "EnableAutoType", "False")
    put(el, "EnableSearching", "False")
    put(el, "LastTopVisibleEntry", b64_uuid("entry"))
    put(el, "PreviousParentGroup", b64_uuid("templates"))
    # Разделитель — запятая: проверка, что ядро не нормализует теги при сохранении.
    put(el, "Tags", "g1,g2")
    put_custom_data(kp, el, "X-Group-Key", "group-value", 15)
    put_unknown(el)
    return work


def fill_all_fields_entry(kp, work):
    entry = kp.add_entry(work, "All Fields", "af-user", "af-pass-1", url="https://af.example.com",
                         notes="entry notes")
    set_uuid(entry, "entry")
    entry.set_custom_property("Custom Plain", "plain-value")
    entry.set_custom_property("Custom Secret", "secret-value", protect=True)
    entry.add_attachment(kp.add_binary(ATTACHMENT_DATA), ATTACHMENT_NAME)

    el = entry._element
    put(el, "IconID", "12")
    put(el, "CustomIconUUID", b64_uuid("icon"))
    put(el, "ForegroundColor", "#112233")
    put(el, "BackgroundColor", "#445566")
    put(el, "OverrideURL", "cmd://firefox {URL}")
    put(el, "Tags", "alpha;beta&gamma")
    put(el, "QualityCheck", "False")
    put(el, "PreviousParentGroup", b64_uuid("templates"))
    put_times(kp, el, 20)

    auto_type = el.find("AutoType")
    if auto_type is None:
        auto_type = put(el, "AutoType", None)
    put(auto_type, "Enabled", "False")
    put(auto_type, "DataTransferObfuscation", "1")
    put(auto_type, "DefaultSequence", "{PASSWORD}{ENTER}")
    association = SubElement(auto_type, "Association")
    SubElement(association, "Window").text = "Firefox*"
    SubElement(association, "KeystrokeSequence").text = "{USERNAME}"

    put_custom_data(kp, el, "X-Entry-Key", "entry-value", 25)
    put_unknown(el, with_secret=True)

    # История: копия записи со всеми полями выше, затем текущая версия меняется.
    entry.save_history()
    entry.password = "af-pass-2"
    return entry


# Порядок элементов как у KeePassXC (KdbxXmlWriter). pykeepass дописывает новые
# элементы в конец (Password после History, AutoType до String) — выравниваем, чтобы
# фикстура выглядела как файл настоящего клиента. Неизвестные теги — перед детьми.
ENTRY_ORDER = ["UUID", "IconID", "CustomIconUUID", "ForegroundColor", "BackgroundColor",
               "OverrideURL", "Tags", "Times", "QualityCheck", "PreviousParentGroup", "String",
               "Binary", "AutoType", "CustomData", AF_UNKNOWN_TAG, "History"]
GROUP_ORDER = ["UUID", "Name", "Notes", "Tags", "IconID", "CustomIconUUID", "Times", "IsExpanded",
               "DefaultAutoTypeSequence", "EnableAutoType", "EnableSearching",
               "LastTopVisibleEntry", "CustomData", "PreviousParentGroup", AF_UNKNOWN_TAG,
               "Entry", "Group"]


def reorder(el, order):
    children = sorted(el, key=lambda c: order.index(c.tag))  # sorted стабилен: String по порядку
    for child in children:
        el.append(child)  # append переносит существующий элемент в конец


def canonical_order(kp):
    root = kp.tree.getroot()
    for group in root.iter("Group"):
        reorder(group, GROUP_ORDER)
    for entry in root.iter("Entry"):
        reorder(entry, ENTRY_ORDER)
        # В шаблоне pykeepass пустая Association — у настоящих клиентов её нет.
        for assoc in entry.findall("AutoType/Association"):
            if not assoc.findtext("Window"):
                assoc.getparent().remove(assoc)


def fill_deleted_objects(kp):
    root_el = kp.tree.getroot().find("Root")
    deleted = root_el.find("DeletedObjects")
    if deleted is None:
        deleted = SubElement(root_el, "DeletedObjects")
    obj = SubElement(deleted, "DeletedObject")
    SubElement(obj, "UUID").text = b64_uuid("deleted")
    SubElement(obj, "DeletionTime").text = af_time(kp, 28)


def verify_all_fields(db_path):
    kp = PyKeePass(str(db_path), password=PASSWORD)
    assert kp.kdbx.header.value.major_version == 4
    assert kp.kdbx.header.value.minor_version == 1, "ожидался KDBX 4.1"
    root = kp.tree.getroot()
    meta = root.find("Meta")
    for tag in ("Color", "MasterKeyChangeForceOnce", "RecycleBinChanged", "LastTopVisibleGroup",
                AF_UNKNOWN_TAG):
        assert meta.find(tag) is not None, tag
    assert meta.find("RecycleBinEnabled").text == "False"

    entry = kp.find_entries(title="All Fields", first=True)
    assert entry.password == "af-pass-2"
    assert entry.get_custom_property("Custom Secret") == "secret-value"
    assert len(entry.history) == 1 and entry.history[0].password == "af-pass-1"
    for tag in ("OverrideURL", "ForegroundColor", "QualityCheck", "PreviousParentGroup", AF_UNKNOWN_TAG):
        assert entry._element.find(tag) is not None, tag
        assert entry.history[0]._element.find(tag) is not None, "history: " + tag
    assert entry._element.findtext(AF_UNKNOWN_TAG + "/Value") == AF_UNKNOWN_SECRET
    assert root.find("Root/DeletedObjects/DeletedObject") is not None


def build_all_fields_fixture():
    db_path = OUT_DIR / ALL_FIELDS_FIXTURE
    if db_path.exists():
        db_path.unlink()

    kp = create_database(str(db_path), password=PASSWORD)
    kp.kdbx.header.value.minor_version = 1

    header = kp.kdbx.header.value.dynamic_header
    header.cipher_id.data = "aes256"
    header.encryption_iv.data = os.urandom(IV_LENGTHS["aes256"])
    params = header.kdf_parameters.data.dict
    params["$UUID"].value = kdf_uuids["argon2id"]
    params["M"].value = FAST_ARGON2["memory_mb"] * 1024 * 1024
    params["I"].value = FAST_ARGON2["iterations"]
    params["P"].value = FAST_ARGON2["parallelism"]

    fill_all_fields_meta(kp)
    work = fill_all_fields_groups(kp)
    fill_all_fields_entry(kp, work)
    fill_deleted_objects(kp)
    canonical_order(kp)
    kp.save()
    verify_all_fields(db_path)
    return db_path


# --- Фикстура «ёршик»: неизвестные элементы на всех уровнях (Step 18) ---------
#
# Ядро хранит и пишет обратно незнакомый тег только у Meta / Group / Entry
# (XmlReader::keep_unknown). Глубже — внутри Times, AutoType, CustomData/Item,
# MemoryProtection, CustomIcons, DeletedObject, на уровне Root / KeePassFile —
# элемент читается и молча выбрасывается: пересохранение чужой базы теряет данные.
#
# Здесь незнакомый тег стоит на КАЖДОМ уровне сразу, свой на каждом месте — по
# имени в diff видно, какой уровень потерян. Плюс вложенность (тег в теге) и
# protected-значения внутри неизвестных элементов: inner stream идёт по порядку
# документа, и если такое значение не вернуть на то же место, все следующие
# пароли расшифруются мусором.
UNKNOWN_FIXTURE = "unknown_everywhere_41.kdbx"

UNK_UUIDS = {
    "group": "7b1e5c60-0000-4000-8000-000000000001",
    "entry": "7b1e5c60-0000-4000-8000-000000000010",
    "icon": "7b1e5c60-0000-4000-8000-000000000020",
    "deleted": "7b1e5c60-0000-4000-8000-000000000030",
}

# Тег на каждое место: имя = где стоит. По имени в diff видно потерянный уровень.
UNK_TAGS = {
    "file": "XFileUnknown",
    "meta": "XMetaUnknown",
    "memory_protection": "XProtectUnknown",
    "custom_icons": "XIconsUnknown",
    "icon": "XIconUnknown",
    "meta_item": "XMetaItemUnknown",
    "root": "XRootUnknown",
    "deleted_objects": "XDeletedObjectsUnknown",
    "deleted_object": "XDeletedObjectUnknown",
    "group": "XGroupUnknown",
    "group_times": "XGroupTimesUnknown",
    "group_item": "XGroupItemUnknown",
    "entry": "XEntryUnknown",
    "entry_times": "XEntryTimesUnknown",
    "auto_type": "XAutoTypeUnknown",
    "association": "XAssociationUnknown",
    "string": "XStringUnknown",
    "binary": "XBinaryUnknown",
    "entry_item": "XEntryItemUnknown",
    "history_entry": "XHistoryEntryUnknown",
    "history_times": "XHistoryTimesUnknown",
}

UNK_ATTR = ("Origin", "step-18 & <fixture>")
UNK_NESTED_TAGS = ("Level1", "Level2", "Level3")
UNK_NESTED_TEXT = "deep & nested"
# Два protected-значения в разных местах дерева: одно до String записи (Times),
# одно после (CustomData) — сдвиг inner stream в любую сторону портит пароли.
UNK_SECRET_TIMES = "secret-in-times"
UNK_SECRET_ITEM = "secret-in-custom-data"


def unk_uuid(key):
    return base64.b64encode(uuid_mod.UUID(UNK_UUIDS[key]).bytes).decode("ascii")


def set_unk_uuid(obj, key):
    obj._element.find("UUID").text = unk_uuid(key)


def add_unknown(parent, where, secret=None, nested=False):
    """Неизвестный элемент в parent: атрибут, текстовый лист, опционально вложенность."""
    el = SubElement(parent, UNK_TAGS[where])
    el.set(*UNK_ATTR)
    SubElement(el, "Inner").text = "value for %s" % where
    if nested:
        # Тег в теге в теге: хранение с путём должно работать на любой глубине.
        node = el
        for tag in UNK_NESTED_TAGS:
            node = SubElement(node, tag)
        node.text = UNK_NESTED_TEXT
    if secret is not None:
        # pykeepass шифрует при сохранении любой Value[@Protected='True']
        SubElement(el, "Value", Protected="True").text = secret
    return el


def fill_unknown_meta(kp):
    meta = kp.tree.getroot().find("Meta")

    protection = meta.find("MemoryProtection")
    if protection is None:
        protection = put(meta, "MemoryProtection", None)
    add_unknown(protection, "memory_protection")

    icons = meta.find("CustomIcons")
    if icons is None:
        icons = put(meta, "CustomIcons", None)
    icon = SubElement(icons, "Icon")
    SubElement(icon, "UUID").text = unk_uuid("icon")
    SubElement(icon, "Data").text = base64.b64encode(AF_ICON_PNG).decode("ascii")
    add_unknown(icon, "icon")
    add_unknown(icons, "custom_icons")

    custom_data = meta.find("CustomData")
    if custom_data is None:
        custom_data = put(meta, "CustomData", None)
    item = SubElement(custom_data, "Item")
    SubElement(item, "Key").text = "X-Meta-Key"
    SubElement(item, "Value").text = "meta-value"
    add_unknown(item, "meta_item")
    add_unknown(meta, "meta")


def fill_unknown_group(kp):
    group = kp.add_group(kp.root_group, "Unknown & Co")
    set_unk_uuid(group, "group")
    el = group._element
    put_times(kp, el, 10)
    add_unknown(el.find("Times"), "group_times")
    custom_data = put(el, "CustomData", None)
    item = SubElement(custom_data, "Item")
    SubElement(item, "Key").text = "X-Group-Key"
    SubElement(item, "Value").text = "group-value"
    add_unknown(item, "group_item")
    add_unknown(el, "group")
    return group


def fill_unknown_entry(kp, group):
    entry = kp.add_entry(group, "Unknown Everywhere", "unk-user", "unk-pass-1",
                         url="https://unknown.example.com", notes="entry with unknown elements")
    set_unk_uuid(entry, "entry")
    entry.set_custom_property("Custom Secret", "secret-value", protect=True)
    entry.add_attachment(kp.add_binary(ATTACHMENT_DATA), ATTACHMENT_NAME)

    el = entry._element
    put_times(kp, el, 20)

    # История создаётся ДО неизвестных элементов: иначе их копии попадут в версию
    # истории и каждый тег встретится в файле дважды. Версии истории нужны свои.
    entry.save_history()
    entry.password = "unk-pass-2"

    # Секрет внутри Times — по порядку документа раньше String записи.
    add_unknown(el.find("Times"), "entry_times", secret=UNK_SECRET_TIMES)

    auto_type = el.find("AutoType")
    if auto_type is None:
        auto_type = put(el, "AutoType", None)
    # В шаблоне pykeepass пустая Association — у настоящих клиентов её нет
    for assoc in auto_type.findall("Association"):
        if not assoc.findtext("Window"):
            auto_type.remove(assoc)
    association = SubElement(auto_type, "Association")
    SubElement(association, "Window").text = "Firefox*"
    SubElement(association, "KeystrokeSequence").text = "{USERNAME}"
    add_unknown(association, "association")
    add_unknown(auto_type, "auto_type")

    for string_el in el.findall("String"):
        if string_el.findtext("Key") == "Title":
            add_unknown(string_el, "string")
    for binary_el in el.findall("Binary"):
        add_unknown(binary_el, "binary")

    custom_data = put(el, "CustomData", None)
    item = SubElement(custom_data, "Item")
    SubElement(item, "Key").text = "X-Entry-Key"
    SubElement(item, "Value").text = "entry-value"
    # Секрет внутри CustomData — позже String записи.
    add_unknown(item, "entry_item", secret=UNK_SECRET_ITEM)
    add_unknown(el, "entry", nested=True)

    history_entry = el.find("History/Entry")
    add_unknown(history_entry, "history_entry")
    add_unknown(history_entry.find("Times"), "history_times")
    return entry


def fill_unknown_root(kp):
    root_el = kp.tree.getroot()
    root_group_el = root_el.find("Root")
    deleted = root_group_el.find("DeletedObjects")
    if deleted is None:
        deleted = SubElement(root_group_el, "DeletedObjects")
    obj = SubElement(deleted, "DeletedObject")
    SubElement(obj, "UUID").text = unk_uuid("deleted")
    SubElement(obj, "DeletionTime").text = af_time(kp, 28)
    add_unknown(obj, "deleted_object")
    add_unknown(deleted, "deleted_objects")
    add_unknown(root_group_el, "root")
    add_unknown(root_el, "file")


def verify_unknown_fixture(db_path):
    kp = PyKeePass(str(db_path), password=PASSWORD)
    assert kp.kdbx.header.value.minor_version == 1, "ожидался KDBX 4.1"
    root = kp.tree.getroot()
    for where, tag in UNK_TAGS.items():
        found = root.findall(".//" + tag)
        assert len(found) == 1, "%s: %d" % (where, len(found))
        assert found[0].get(UNK_ATTR[0]) == UNK_ATTR[1], where
        assert found[0].findtext("Inner") == "value for %s" % where, where
    entry = kp.find_entries(title="Unknown Everywhere", first=True)
    assert entry.password == "unk-pass-2"
    assert len(entry.history) == 1 and entry.history[0].password == "unk-pass-1"
    assert entry.get_custom_property("Custom Secret") == "secret-value"
    deep = root.find(".//%s/%s" % (UNK_TAGS["entry"], "/".join(UNK_NESTED_TAGS)))
    assert deep is not None and deep.text == UNK_NESTED_TEXT
    times_secret = entry._element.findtext("Times/%s/Value" % UNK_TAGS["entry_times"])
    assert times_secret == UNK_SECRET_TIMES, times_secret


def build_unknown_fixture():
    db_path = OUT_DIR / UNKNOWN_FIXTURE
    if db_path.exists():
        db_path.unlink()

    kp = create_database(str(db_path), password=PASSWORD)
    kp.kdbx.header.value.minor_version = 1

    header = kp.kdbx.header.value.dynamic_header
    header.cipher_id.data = "aes256"
    header.encryption_iv.data = os.urandom(IV_LENGTHS["aes256"])
    params = header.kdf_parameters.data.dict
    params["$UUID"].value = kdf_uuids["argon2id"]
    params["M"].value = FAST_ARGON2["memory_mb"] * 1024 * 1024
    params["I"].value = FAST_ARGON2["iterations"]
    params["P"].value = FAST_ARGON2["parallelism"]

    fill_unknown_meta(kp)
    group = fill_unknown_group(kp)
    fill_unknown_entry(kp, group)
    fill_unknown_root(kp)
    kp.save()
    verify_unknown_fixture(db_path)
    return db_path


# --- Фикстура граничных значений (Step 19) -----------------------------------
#
# Оракул Step 17 проверял «каждый элемент заполнен», но не «чем именно заполнен».
# Здесь значения, на которых обычно и ломаются парсеры: юникод и эмодзи (включая
# суррогатные пары), пустые и пробельные поля, многострочный текст, очень длинные
# строки, спецсимволы XML в ключах полей, пустое вложение и одно и то же вложение
# в разных записях и в истории, CustomData в том виде, как его пишет KeePassXC.
EDGE_FIXTURE = "edge_values_41.kdbx"

EDGE_UUIDS = {
    "group": "3c7a9e10-0000-4000-8000-000000000001",
    "entry": "3c7a9e10-0000-4000-8000-000000000010",
    "entry2": "3c7a9e10-0000-4000-8000-000000000011",
}

# Эмодзи вне BMP (суррогатная пара в UTF-16), комбинирующая диакритика, нулевая ширина,
# управляющие символы направления письма, иероглифы, математический алфавит
EDGE_UNICODE = "спам \U0001F510\U0001F1FA\U0001F1E6 é ​ ‮RTL‬ 中文 \U0001D54F"
EDGE_MULTILINE = "первая строка\nвторая строка\r\nтретья\tс табом\n\nпустая выше"
EDGE_LONG = "длинная-" * 12000  # ~96 КБ в одном поле
EDGE_SPACES = "   "
EDGE_XML_CHARS = 'a & b < c > d " e'
EDGE_KEY_WITH_XML = 'Ключ & <со> "спецсимволами"'

# KeePassXC пишет в CustomData записи свои ключи браузерной интеграции
EDGE_KPXC = [
    ("KPXC_BROWSER_example.com", "true"),
    ("_LAST_MODIFIED", "Sun Jan 12 03:51:58 2020 GMT"),
]


def edge_uuid(key):
    return base64.b64encode(uuid_mod.UUID(EDGE_UUIDS[key]).bytes).decode("ascii")


def fill_edge_entry(kp, group, binary_id):
    entry = kp.add_entry(group, EDGE_UNICODE, "user " + EDGE_UNICODE, "пароль \U0001F510 & <x>",
                         url="https://example.com/?a=1&b=2", notes=EDGE_MULTILINE)
    entry._element.find("UUID").text = edge_uuid("entry")

    entry.set_custom_property("Пустое", "")
    entry.set_custom_property("Пробелы", EDGE_SPACES)
    entry.set_custom_property("Длинное", EDGE_LONG)
    # Ключ со спецсимволами добавляем через lxml: pykeepass строит XPath по ключу
    # и ломается на кавычках
    field = SubElement(entry._element, "String")
    SubElement(field, "Key").text = EDGE_KEY_WITH_XML
    SubElement(field, "Value").text = EDGE_XML_CHARS
    # Пустое protected-значение: inner stream не должен на нём спотыкаться
    entry.set_custom_property("Пустой секрет", "", protect=True)
    entry.set_custom_property("Секрет", "значение \U0001F510", protect=True)

    put(entry._element, "Tags", "тег-один;тег & два;\U0001F510")

    custom_data = put(entry._element, "CustomData", None)
    for key, value in EDGE_KPXC:
        item = SubElement(custom_data, "Item")
        SubElement(item, "Key").text = key
        SubElement(item, "Value").text = value

    # Одно и то же вложение и пустое вложение
    entry.add_attachment(binary_id, "общий.txt")
    entry.add_attachment(kp.add_binary(b""), "пустой.bin")

    # История: версия с теми же вложениями
    entry.save_history()
    entry.password = "пароль-2 \U0001F510"
    return entry


def fill_edge_second_entry(kp, group, binary_id):
    # То же самое вложение во второй записи: при сохранении оно не должно задвоиться
    # или потеряться у одной из записей
    entry = kp.add_entry(group, "Вторая", "", "", url="", notes="")
    entry._element.find("UUID").text = edge_uuid("entry2")
    entry.add_attachment(binary_id, "общий.txt")
    return entry


def verify_edge_fixture(db_path):
    kp = PyKeePass(str(db_path), password=PASSWORD)
    assert kp.kdbx.header.value.minor_version == 1, "ожидался KDBX 4.1"
    # Поиск по заголовку тут не годится: pykeepass строит XPath и ломается на кавычках
    def by_uuid(key):
        wanted = uuid_mod.UUID(EDGE_UUIDS[key])
        return next((e for e in kp.entries if e.uuid == wanted), None)

    entry = by_uuid("entry")
    assert entry is not None, "запись с юникодом в заголовке не найдена"
    assert entry.title == EDGE_UNICODE
    assert entry.notes == EDGE_MULTILINE
    assert entry.get_custom_property("Длинное") == EDGE_LONG
    assert entry.get_custom_property("Секрет") == "значение \U0001F510"
    # Пустое protected-значение pykeepass отдаёт как None: важно, что поле в файле есть
    assert entry.get_custom_property("Пустой секрет") in (None, "")
    values = {f.findtext("Key"): f.findtext("Value") for f in entry._element.findall("String")}
    assert values[EDGE_KEY_WITH_XML] == EDGE_XML_CHARS
    assert values["Пробелы"] == EDGE_SPACES
    assert "Пустой секрет" in values and "Пустое" in values
    names = sorted(a.filename for a in entry.attachments)
    assert names == ["общий.txt", "пустой.bin"], names
    assert len(entry.history) == 1
    second = by_uuid("entry2")
    assert [a.filename for a in second.attachments] == ["общий.txt"]


def build_edge_fixture():
    db_path = OUT_DIR / EDGE_FIXTURE
    if db_path.exists():
        db_path.unlink()

    kp = create_database(str(db_path), password=PASSWORD)
    kp.kdbx.header.value.minor_version = 1

    header = kp.kdbx.header.value.dynamic_header
    header.cipher_id.data = "aes256"
    header.encryption_iv.data = os.urandom(IV_LENGTHS["aes256"])
    params = header.kdf_parameters.data.dict
    params["$UUID"].value = kdf_uuids["argon2id"]
    params["M"].value = FAST_ARGON2["memory_mb"] * 1024 * 1024
    params["I"].value = FAST_ARGON2["iterations"]
    params["P"].value = FAST_ARGON2["parallelism"]

    group = kp.add_group(kp.root_group, "Группа & <граничная> \U0001F510")
    group._element.find("UUID").text = edge_uuid("group")
    put(group._element, "Notes", EDGE_MULTILINE)

    binary_id = kp.add_binary(ATTACHMENT_DATA)
    fill_edge_entry(kp, group, binary_id)
    fill_edge_second_entry(kp, group, binary_id)

    kp.save()
    verify_edge_fixture(db_path)
    return db_path


def write_xml_key_file(path):
    """XML KeyFile v2 — формат, который понимает наш core (src/db/file_key.rs).

    <Data> — 32 байта ключа в hex, Hash — первые 4 байта SHA-256 от этих байт.
    """
    key = os.urandom(32)
    checksum = hashlib.sha256(key).digest()[:4]
    data_hex = key.hex().upper()
    # KeePassXC разбивает hex на группы по 8 символов — делаем так же
    grouped = " ".join(data_hex[i:i + 8] for i in range(0, len(data_hex), 8))
    path.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        "<KeyFile>\n"
        "    <Meta>\n"
        "        <Version>2.0</Version>\n"
        "    </Meta>\n"
        "    <Key>\n"
        '        <Data Hash="%s">%s</Data>\n'
        "    </Key>\n"
        "</KeyFile>\n" % (checksum.hex().upper(), grouped),
        encoding="utf-8",
    )
    return path


def fill_content(kp):
    """Одинаковое содержимое во всех фикстурах, чтобы Rust-тесты были общими.

    Покрывает: обычные записи, подгруппу, protected-значения (пароль + TOTP)
    и binaries (аттачмент).
    """
    root = kp.root_group

    kp.add_entry(root, "GitHub", "octocat", "gh-secret-1", url="https://github.com")
    kp.add_entry(root, "Email", "user@example.com", "mail-secret-2", url="https://mail.example.com")

    work = kp.add_group(root, "Work")
    entry = kp.add_entry(work, "Server", "admin", "srv-secret-3", url="ssh://10.0.0.1")
    entry.notes = "fixture entry with attachment and totp"
    entry.otp = TOTP_URL

    binary_id = kp.add_binary(ATTACHMENT_DATA)
    entry.add_attachment(binary_id, ATTACHMENT_NAME)


def build(name, cipher, kdf, argon2, use_key_file):
    db_path = OUT_DIR / name
    key_file_path = db_path.with_suffix(".keyx") if use_key_file else None

    if db_path.exists():
        db_path.unlink()
    if key_file_path is not None:
        if key_file_path.exists():
            key_file_path.unlink()
        write_xml_key_file(key_file_path)

    # create_database копирует вшитый в пакет шаблон (KDBX 4.0, AES-256, Argon2d).
    kp = create_database(
        str(db_path),
        password=PASSWORD,
        keyfile=str(key_file_path) if key_file_path else None,
    )

    # Шифр и KDF в API не выставлены — правим construct-структуры header напрямую.
    header = kp.kdbx.header.value.dynamic_header
    header.cipher_id.data = cipher
    header.encryption_iv.data = os.urandom(IV_LENGTHS[cipher])

    params = header.kdf_parameters.data.dict
    params["$UUID"].value = kdf_uuids[kdf]
    params["M"].value = argon2["memory_mb"] * 1024 * 1024  # в байтах
    params["I"].value = argon2["iterations"]
    params["P"].value = argon2["parallelism"]

    fill_content(kp)
    kp.save()  # правки header применяются только здесь
    return db_path, key_file_path


def verify(db_path, key_file_path):
    """Перечитать файл сторонней реализацией — базовая проверка, что он валиден."""
    kp = PyKeePass(
        str(db_path),
        password=PASSWORD,
        keyfile=str(key_file_path) if key_file_path else None,
    )
    titles = sorted(entry.title for entry in kp.entries)
    assert titles == ["Email", "GitHub", "Server"], titles
    assert sorted(group.name for group in kp.groups) == ["Root", "Work"]

    server = kp.find_entries(title="Server", first=True)
    assert server.password == "srv-secret-3"
    assert server.otp == TOTP_URL
    attachments = [(a.filename, a.data) for a in server.attachments]
    assert attachments == [(ATTACHMENT_NAME, ATTACHMENT_DATA)], attachments
    return titles


def main():
    if shutil.which("git") and not OUT_DIR.exists():
        OUT_DIR.mkdir(parents=True)

    print("Фикстуры -> %s" % OUT_DIR)
    print("Пароль всех баз: %s" % PASSWORD)
    for name, cipher, kdf, argon2, use_key_file in FIXTURES:
        db_path, key_file_path = build(name, cipher, kdf, argon2, use_key_file)
        verify(db_path, key_file_path)
        print(
            "  OK  %-34s %-9s %-9s %2d MB / %2d iter / P=%d%s"
            % (
                name,
                cipher,
                kdf,
                argon2["memory_mb"],
                argon2["iterations"],
                argon2["parallelism"],
                "  + %s" % key_file_path.name if key_file_path else "",
            )
        )
    build_preservation_fixture()
    print(
        "  OK  %-34s %-9s %-9s %2d MB / %2d iter / P=%d  (passkey/SFTP/WebDAV/AutoOpen)"
        % (PRESERVATION_FIXTURE, "aes256", "argon2id", FAST_ARGON2["memory_mb"],
           FAST_ARGON2["iterations"], FAST_ARGON2["parallelism"])
    )
    build_all_fields_fixture()
    print(
        "  OK  %-34s %-9s %-9s %2d MB / %2d iter / P=%d  (KDBX 4.1, все элементы не по умолчанию)"
        % (ALL_FIELDS_FIXTURE, "aes256", "argon2id", FAST_ARGON2["memory_mb"],
           FAST_ARGON2["iterations"], FAST_ARGON2["parallelism"])
    )
    build_unknown_fixture()
    print(
        "  OK  %-34s %-9s %-9s %2d MB / %2d iter / P=%d  (неизвестные элементы на всех уровнях)"
        % (UNKNOWN_FIXTURE, "aes256", "argon2id", FAST_ARGON2["memory_mb"],
           FAST_ARGON2["iterations"], FAST_ARGON2["parallelism"])
    )
    build_edge_fixture()
    print(
        "  OK  %-34s %-9s %-9s %2d MB / %2d iter / P=%d  (граничные значения полей)"
        % (EDGE_FIXTURE, "aes256", "argon2id", FAST_ARGON2["memory_mb"],
           FAST_ARGON2["iterations"], FAST_ARGON2["parallelism"])
    )

    print("\nДальше: python tools/kdbx-oracle/dump_header.py tests/resources/*.kdbx")
    return 0


if __name__ == "__main__":
    sys.exit(main())
