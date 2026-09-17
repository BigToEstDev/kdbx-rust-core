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

    print("\nДальше: python tools/kdbx-oracle/dump_header.py tests/resources/*.kdbx")
    return 0


if __name__ == "__main__":
    sys.exit(main())
