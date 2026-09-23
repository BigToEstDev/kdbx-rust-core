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


def put_unknown(obj_el):
    unknown = put(obj_el, AF_UNKNOWN_TAG, None)
    unknown.set(*AF_UNKNOWN_ATTR)
    SubElement(unknown, AF_UNKNOWN_CHILD[0]).text = AF_UNKNOWN_CHILD[1]


def fill_all_fields_meta(kp):
    meta = kp.tree.getroot().find("Meta")
    put(meta, "DatabaseName", "All Fields 4.1")
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

    work = kp.add_group(root, "Work")
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
    put(el, "Tags", "alpha;beta")
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
    put_unknown(el)

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

    print("\nДальше: python tools/kdbx-oracle/dump_header.py tests/resources/*.kdbx")
    return 0


if __name__ == "__main__":
    sys.exit(main())
