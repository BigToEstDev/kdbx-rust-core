"""Проверяет, что базы, записанные НАШИМ ядром, читаются сторонней реализацией.

Обратная сторона tests/foreign_fixtures.rs: там наш core читает чужие файлы, здесь
чужой код читает наши. Вместе они закрывают оба направления совместимости с KDBX4.

Запускает `cargo run --example write_roundtrip_dbs`, который пишет базы во временную
директорию, затем открывает каждую через pykeepass и сверяет шифр/KDF в заголовке и содержимое.

Это отдельный шаг, а НЕ часть `cargo test`: Python не должен быть обязательной
зависимостью для сборки и прогона тестов Rust-крейта.

Использование (из корня pass-rust-core):
    .venv/Scripts/python.exe tools/kdbx-oracle/verify_roundtrip.py
"""

import base64
import json
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    # Windows-консоль не utf-8 по умолчанию
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

from pykeepass import PyKeePass
from pykeepass.kdbx_parsing.kdbx4 import kdf_uuids

REPO_ROOT = Path(__file__).resolve().parents[2]

# Должно совпадать с константами в crates/kdbx-rust-core/examples/write_roundtrip_dbs.rs
PASSWORD = "test-pass-1234"
ATTACHMENT_NAME = "notes.txt"
ATTACHMENT_DATA = b"example doc\n2 lines\n"
OLD_ATTACHMENT_NAME = "old.txt"
OLD_ATTACHMENT_DATA = b"removed by the second edit\n"
PHOTO_ATTACHMENT_NAME = "photo.bin"
PHOTO_ATTACHMENT_DATA = bytes(range(256))
TOTP_URL = "otpauth://totp/server?secret=JBSWY3DPEHPK3PXP&issuer=demo&algorithm=SHA1&digits=6&period=30"

EXPECTED_TITLES = ["Email", "GitHub", "Server", "Trashed"]
# Наше ядро называет корневую группу по имени базы (database_name в NewDatabase),
# а не фиксированным "Root", как шаблон pykeepass. Это поведение нашего кода, не формата.
EXPECTED_GROUPS = ["Recycle Bin", "RoundTripDb", "Work"]
# Имена из вывода write_roundtrip_dbs (как в serde нашего ядра) -> значения в заголовке по pykeepass.
# Сверяем заголовок, а не только факт открытия: файл, записанный не тем KDF/шифром, но
# внутренне согласованный, откроется без ошибок (так и пропустили баг Argon2Kdf.variant).
# Сжатие в заголовке, как его читает pykeepass (Step 64)
EXPECTED_COMPRESSION = {"GZip": True, "None": False}
# Скрытые поля базы, `Meta/MemoryProtection/Protect<имя>` (Step 66)
PROTECTION_NAMES = ["Title", "UserName", "Password", "URL", "Notes"]

EXPECTED_CIPHERS = {"Aes256": "aes256", "ChaCha20": "chacha20"}
EXPECTED_KDF_UUIDS = {"Argon2d": kdf_uuids["argon2"], "Argon2id": kdf_uuids["argon2id"]}

EXPECTED_PASSWORDS = {
    "GitHub": "gh-secret-1",
    "Email": "mail-secret-2",
    "Server": "srv-secret-3",
    "Trashed": "old-secret-4",
}


# Слитая база (Step 106): фикстуры pykeepass merge_*.kdbx, копия слита, другая база импортирована
MERGED_TITLES = ["Added", "Edited", "Foreign", "Kept"]
MERGED_DELETED_UUID = "6c3d9a10-0000-4000-8000-000000000003"


def write_databases(out_dir):
    """Просит наше ядро записать базы. Возвращает (список (путь, шифр, kdf, key-file, сжатие, скрытые поля),
    путь слитой базы)."""
    result = subprocess.run(
        [
            "cargo",
            "run",
            "--quiet",
            "-p",
            "kdbx-rust-core",
            "--example",
            "write_roundtrip_dbs",
            "--",
            str(out_dir),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print("cargo run упал:\n%s\n%s" % (result.stdout, result.stderr))
        raise SystemExit(1)

    databases = []
    merged = None
    for line in result.stdout.splitlines():
        if line.startswith("merged|"):
            merged = line.strip().split("|", 1)[1]
            continue
        # Пример печатает: путь|шифр|kdf|key-file|сжатие|скрытые поля через запятую (key-file может быть пустым)
        parts = line.strip().split("|")
        if len(parts) == 6 and parts[0].endswith(".kdbx"):
            path, cipher, kdf, key_file, compression, protected = parts
            databases.append((path, cipher, kdf, key_file or None, compression, protected.split(",")))

    if not databases or merged is None:
        print("пример не напечатал базы или слитую базу; вывод был:\n%s" % result.stdout)
        raise SystemExit(1)
    return databases, merged


def verify_merged(path):
    """Слитая и сохранённая нашим ядром база: записи обеих, правка копии с версией, удаление — в DeletedObjects."""
    kp = PyKeePass(path, password=PASSWORD)

    titles = sorted(entry.title for entry in kp.entries)
    assert titles == MERGED_TITLES, "записи: %s" % titles

    edited = kp.find_entries(title="Edited", first=True)
    assert edited.password == "new-secret", "Edited: пароль %r" % edited.password
    assert [h.password for h in edited.history] == ["old-secret"], "версии Edited"
    assert kp.find_entries(title="Foreign", first=True).password == "foreign-secret"

    deleted = [el.text for el in kp.tree.getroot().findall("Root/DeletedObjects/DeletedObject/UUID")]
    expected = base64.b64encode(uuid.UUID(MERGED_DELETED_UUID).bytes).decode("ascii")
    assert expected in deleted, "удаление Deleted не в DeletedObjects: %s" % deleted


def verify_header(kp, cipher, kdf, compression):
    """Шифр, KDF и сжатие в заголовке должны совпадать с тем, что заявил пример."""
    header = kp.kdbx.header.value.dynamic_header

    written_compression = header.compression_flags.data.compression
    assert written_compression == EXPECTED_COMPRESSION[compression], "сжатие: заявлено %s, записано %s" % (
        compression,
        written_compression,
    )

    written_cipher = header.cipher_id.data
    assert written_cipher == EXPECTED_CIPHERS[cipher], "шифр: заявлен %s, записан %s" % (
        cipher,
        written_cipher,
    )

    written_kdf = header.kdf_parameters.data.dict["$UUID"].value
    names = {value: name for name, value in EXPECTED_KDF_UUIDS.items()}
    assert written_kdf == EXPECTED_KDF_UUIDS[kdf], "KDF: заявлен %s, записан %s" % (
        kdf,
        names.get(written_kdf, written_kdf.hex()),
    )


def verify_protection(kp, protected):
    """Скрытые поля в `Meta/MemoryProtection` должны совпадать с тем, что заявил пример."""
    for name in PROTECTION_NAMES:
        element = kp.tree.find("Meta/MemoryProtection/Protect%s" % name)
        assert element is not None, "нет Meta/MemoryProtection/Protect%s" % name
        written = element.text == "True"
        assert written == (name in protected), "Protect%s: заявлено %s, записано %r" % (
            name,
            name in protected,
            element.text,
        )


def verify_recycle_bin(kp):
    """Удалённая запись лежит в корзине из `Meta`, прежняя группа — в `PreviousParentGroup` (Step 69)."""
    enabled = kp.tree.find("Meta/RecycleBinEnabled")
    assert enabled is not None and enabled.text == "True", "RecycleBinEnabled: %r" % (
        enabled is not None and enabled.text,
    )
    recycle_bin = kp.recyclebin_group
    assert recycle_bin is not None, "корзины нет в Meta/RecycleBinUUID"

    trashed = kp.find_entries(title="Trashed", first=True)
    assert trashed.parentgroup.uuid == recycle_bin.uuid, "Trashed не в корзине"

    work = kp.find_groups(name="Work", first=True)
    previous = trashed._element.find("PreviousParentGroup")
    assert previous is not None, "у Trashed нет PreviousParentGroup"
    assert previous.text == base64.b64encode(work.uuid.bytes).decode(), "PreviousParentGroup: %r" % previous.text


def verify(path, cipher, kdf, key_file, compression, protected):
    """Открывает базу сторонней реализацией и сверяет заголовок и содержимое."""
    kp = PyKeePass(path, password=PASSWORD, keyfile=key_file)
    verify_header(kp, cipher, kdf, compression)
    verify_protection(kp, protected)
    verify_recycle_bin(kp)

    titles = sorted(entry.title for entry in kp.entries)
    assert titles == EXPECTED_TITLES, "записи: %s" % titles

    groups = sorted(group.name for group in kp.groups)
    assert groups == EXPECTED_GROUPS, "группы: %s" % groups

    # Пароли — protected-значения: если inner-stream шифр записан неверно,
    # расшифровка даст мусор
    for title, expected in EXPECTED_PASSWORDS.items():
        entry = kp.find_entries(title=title, first=True)
        assert entry is not None, "запись %s не найдена" % title
        assert entry.password == expected, "%s: пароль %r" % (title, entry.password)

    server = kp.find_entries(title="Server", first=True)
    assert server.parentgroup.name == "Work", "Server не в группе Work"

    # TOTP — тоже protected-значение
    assert server.otp == TOTP_URL, "otp: %r" % server.otp

    # Тип своего поля (Step 76): поле — обычная строка, тип — в CustomData записи под нашим ключом
    assert server.get_custom_property("Phone") == "+7 900 000-00-00", "поле Phone"
    types = [
        item.findtext("Value")
        for item in server._element.findall("CustomData/Item")
        if item.findtext("Key") == "PassHolder.FieldTypes"
    ]
    assert [json.loads(t) for t in types] == [{"Phone": "phone"}], "типы полей: %s" % types

    # Вложения проверяют inner header (binaries) и ссылки из записи и версии (Step 102): добавлены с формой,
    # old.txt второй правкой убран из записи, но остаётся у последней версии
    def attachments_of(entry):
        return [(a.filename, a.data) for a in entry.attachments]

    def sizes(attachments):
        return [(name, len(data)) for name, data in attachments]

    attachments = attachments_of(server)
    expected = [(ATTACHMENT_NAME, ATTACHMENT_DATA), (PHOTO_ATTACHMENT_NAME, PHOTO_ATTACHMENT_DATA)]
    assert attachments == expected, "вложения: %s" % sizes(attachments)

    # У записей истории pykeepass вложений не отдаёт (`attachments` пуст) — по XML версии: Binary/Key и Ref в
    # бинарники inner header
    version = [
        (b.findtext("Key"), kp.binaries[int(b.find("Value").get("Ref"))])
        for b in server.history[-1]._element.findall("Binary")
    ]
    expected = [(ATTACHMENT_NAME, ATTACHMENT_DATA), (OLD_ATTACHMENT_NAME, OLD_ATTACHMENT_DATA)]
    assert version == expected, "вложения версии: %s" % sizes(version)


def main():
    out_dir = Path(tempfile.mkdtemp(prefix="okp_roundtrip_"))
    try:
        print("Наше ядро пишет базы в %s" % out_dir)
        databases, merged = write_databases(out_dir)

        for path, cipher, kdf, key_file, compression, protected in databases:
            verify(path, cipher, kdf, key_file, compression, protected)
            print(
                "  OK  %-44s %-9s %-9s %-5s %-18s%s"
                % (
                    Path(path).name,
                    cipher,
                    kdf,
                    compression,
                    ",".join(protected),
                    "  + key-file" if key_file else "",
                )
            )

        verify_merged(merged)
        print("  OK  %-44s слияние копии и импорт другой базы" % Path(merged).name)

        print("\nВсе %d баз, записанных нашим ядром, читаются pykeepass." % (len(databases) + 1))
        return 0
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
