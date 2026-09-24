"""Что наше ядро теряет или меняет, когда пересохраняет чужую базу.

Открывает фикстуру нашим ядром и сохраняет в новый файл (`cargo run --example
resave_db`), затем pykeepass расшифровывает оба файла и сравнивает XML поэлементно.
Результат — таблица «элемент → потерян / изменён / добавлен» и код выхода 1, если
отличия есть (кроме законных, см. ALLOWED_CHANGES).

Нормализация перед сравнением:
- объекты адресуются по ключу, а не по позиции: группы, записи, иконки, удалённые
  объекты — по UUID; String / Binary — по Key; CustomData/Item — по Key;
- порядок разноимённых соседних элементов не учитывается (у нашего writer свой
  порядок тегов, KeePass на порядок не смотрит), а порядок групп и записей внутри
  группы — учитывается (отдельный псевдо-элемент `@children`);
- время сравнивается как момент, а не как строка (base64 KDBX4 и ISO равнозначны);
- Binary сравнивается по содержимому вложения, а не по номеру Ref;
- пустой элемент без атрибутов равен отсутствующему (KeePass читает их одинаково);
  то же для нулевого UUID-ссылки и `Protected="False"`;
- отсутствующий элемент равен значению KeePass по умолчанию (DEFAULTS): пропуск
  `<EnableAutoType>null</…>` — не потеря, а запись `IsExpanded=False` вместо
  отсутствующего (по умолчанию True) — изменение.

Контроль самого оракула — тот же файл, пересохранённый pykeepass-ом: отличий быть
не должно, иначе врёт нормализация, а не ядро.

Использование (из корня pass-rust-core):
    .venv/Scripts/python.exe tools/kdbx-oracle/compare_roundtrip.py [фикстура.kdbx ...] [--all]
По умолчанию — tests/resources/all_fields_41.kdbx и okp_entry_types.kdbx.
--all печатает и сохранённые элементы.
"""

import base64
import hashlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    # Windows-консоль не utf-8 по умолчанию
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

from pykeepass import PyKeePass

REPO_ROOT = Path(__file__).resolve().parents[2]
RESOURCES = REPO_ROOT / "tests" / "resources"
PASSWORD = "test-pass-1234"
DEFAULT_FIXTURES = ["all_fields_41.kdbx", "okp_entry_types.kdbx"]

# Законно меняется при каждом сохранении: имя программы, которая записала файл.
# Всё прочее, что попадает сюда, — только с обоснованием в Result степа.
ALLOWED_CHANGES = {
    "Meta/Generator",
}

# Элементы-списки: ребёнок адресуется значением своего ключевого элемента.
KEYED = {
    "Group": "UUID",
    "Entry": "UUID",
    "Icon": "UUID",
    "DeletedObject": "UUID",
    "String": "Key",
    "Binary": "Key",
    "Item": "Key",
}

KDBX_EPOCH = datetime(1, 1, 1, tzinfo=timezone.utc)

# Отсутствующий элемент KeePass читает как значение по умолчанию (KeePassLib: PwGroup,
# PwEntry, PwDatabase, MemoryProtectionConfig). Пропуск такого элемента — не потеря, а
# вот запись другого значения на месте пропуска — изменение (IsExpanded: у KeePass True).
DEFAULTS = {
    "Group/IconID": "48",
    "Group/IsExpanded": "True",
    "Group/EnableAutoType": "null",
    "Group/EnableSearching": "null",
    "Entry/IconID": "0",
    "Entry/QualityCheck": "True",
    "AutoType/DataTransferObfuscation": "0",
    "Meta/MasterKeyChangeRec": "-1",
    "Meta/MasterKeyChangeForce": "-1",
    "Meta/MasterKeyChangeForceOnce": "False",
    "MemoryProtection/ProtectTitle": "False",
    "MemoryProtection/ProtectUserName": "False",
    "MemoryProtection/ProtectPassword": "True",
    "MemoryProtection/ProtectURL": "False",
    "MemoryProtection/ProtectNotes": "False",
}
# Ссылка на «ничего» (LastTopVisibleEntry, LastSelectedGroup…) равна отсутствию ссылки.
ZERO_UUID = base64.b64encode(bytes(16)).decode("ascii")


def default_for(path):
    parts = generic(path).split("/")
    return DEFAULTS.get("/".join(parts[-2:]))


def is_time_tag(tag):
    return tag.endswith("Time") or tag.endswith("Changed")


def normalize_time(text):
    """KDBX4 пишет время как base64 от int64 секунд с 0001-01-01, KDBX3 и экспорт — ISO."""
    try:
        raw = base64.b64decode(text, validate=True)
        if len(raw) == 8:
            seconds = struct.unpack("<q", raw)[0]
            return (KDBX_EPOCH + timedelta(seconds=seconds)).isoformat()
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return text


def leaf_value(kp, el):
    text = el.text or ""
    if el.tag == "Value" and el.getparent().tag == "Binary":
        # Номер Ref законно меняется при перепаковке вложений — сравниваем содержимое.
        ref = el.get("Ref")
        data = kp.binaries[int(ref)] if ref is not None else b""
        return "sha256:" + hashlib.sha256(data).hexdigest()[:16]
    if is_time_tag(el.tag) and text:
        text = normalize_time(text)
    if text == ZERO_UUID:
        text = ""
    # Protected="False" равнозначно отсутствию атрибута.
    attrs = {k: v for k, v in el.attrib.items() if not (k == "Protected" and v == "False")}
    if attrs:
        text += "  " + " ".join("@%s=%s" % kv for kv in sorted(attrs.items()))
    return text


def flatten(kp, el, path, out):
    children = list(el)
    if not children:
        value = leaf_value(kp, el)
        if value:
            out[path] = value
        return

    # Атрибуты у элемента с детьми (неизвестные теги могут их нести).
    for name, value in sorted(el.attrib.items()):
        out["%s/@%s" % (path, name)] = value

    if el.tag == "Group":
        order = ["%s:%s" % (c.tag, c.findtext("UUID")) for c in children if c.tag in ("Group", "Entry")]
        if order:
            out[path + "/@children"] = " ".join(order)

    seen = {}
    for child in children:
        key_tag = KEYED.get(child.tag)
        key = child.findtext(key_tag) if key_tag else None
        if key is not None:
            segment = "%s[%s]" % (child.tag, key)
        else:
            # Повторяющиеся теги без ключа (Association, записи истории) — по позиции.
            n = seen.get(child.tag, 0)
            seen[child.tag] = n + 1
            same = sum(1 for c in children if c.tag == child.tag)
            segment = child.tag if same == 1 else "%s[#%d]" % (child.tag, n)
        if child.getparent().tag == "History" and child.tag == "Entry":
            n = seen.get("History/Entry", 0)
            seen["History/Entry"] = n + 1
            segment = "Entry[#%d]" % n
        flatten(kp, child, path + "/" + segment, out)


def load_flat(db_path, key_file=None):
    kp = open_db(db_path, key_file)
    root = kp.tree.getroot()
    out = {}
    for top in root:
        flatten(kp, top, top.tag, out)
    return kp, out


def diff(before, after):
    rows = []
    for path in sorted(set(before) | set(after)):
        b = before.get(path, default_for(path))
        a = after.get(path, default_for(path))
        if b == a:
            status = "сохранён"
        elif a is None:
            status = "потерян"
        elif b is None:
            status = "добавлен"
        else:
            status = "изменён"
        if status != "сохранён" and generic(path) in ALLOWED_CHANGES:
            status = "законно"
        rows.append((status, path, b, a))
    return rows


def generic(path):
    """Путь без ключей в скобках: Meta/Generator, Root/Group/Entry/OverrideURL…

    Ключи убираются ДО разбиения по "/": UUID в base64 законно содержит "/" и "+",
    и путь Entry[XCr/BLL...] иначе разваливается на лишние сегменты - тогда значение
    по умолчанию для элемента не находится и целый элемент попадает в diff как
    «добавлен» (Step 19).
    """
    without_keys = re.sub(r"\[[^\]]*\]", "", path)
    return without_keys


def key_file_for(db_path):
    """Фикстуре с ключевым файлом соответствует .keyx рядом (gen_fixtures.py)."""
    candidate = Path(db_path).with_suffix(".keyx")
    return candidate if candidate.exists() else None


def open_db(path, key_file=None):
    return PyKeePass(
        str(path),
        password=PASSWORD,
        keyfile=str(key_file) if key_file else None,
    )


def resave_with_core(source, target, key_file=None):
    command = ["cargo", "run", "--quiet", "--example", "resave_db", "--",
               str(source), str(target), PASSWORD]
    if key_file:
        command.append(str(key_file))
    subprocess.run(
        command,
        cwd=REPO_ROOT,
        check=True,
    )


def object_labels(kp):
    """UUID → имя группы / заголовок записи: только для читаемого вывода."""
    labels = {}
    root = kp.tree.getroot()
    for group in root.iter("Group"):
        labels[group.findtext("UUID")] = group.findtext("Name") or "?"
    for entry in root.iter("Entry"):
        title = entry.find("String[Key='Title']/Value")
        labels.setdefault(entry.findtext("UUID"), title.text if title is not None else "?")
    return labels


def readable(path, labels):
    for uuid, label in labels.items():
        path = path.replace("[%s]" % uuid, "[%s]" % label)
    return path


def print_rows(title, rows, show_all, labels=None):
    labels = labels or {}
    counts = {}
    for status, *_ in rows:
        counts[status] = counts.get(status, 0) + 1
    print("\n== %s: %s" % (title, ", ".join("%s %d" % kv for kv in sorted(counts.items()))))
    for status, path, b, a in rows:
        if status == "сохранён" and not show_all:
            continue
        print("  %-9s %s" % (status, readable(path, labels)))
        if status in ("изменён", "законно") and b is not None and a is not None:
            print("            было:  %s" % b)
            print("            стало: %s" % a)
        elif status == "потерян":
            print("            было:  %s" % b)
        elif status == "добавлен":
            print("            стало: %s" % a)
    return sum(n for s, n in counts.items() if s not in ("сохранён", "законно"))


def compare_fixture(fixture, show_all, workdir):
    source = Path(fixture)
    if not source.is_absolute() and not source.exists():
        source = RESOURCES / fixture
    key_file = key_file_for(source)
    kp_before, before = load_flat(source, key_file)
    labels = object_labels(kp_before)

    # Контроль оракула: pykeepass пересохраняет сам себя — отличий быть не должно.
    control = workdir / ("control_" + source.name)
    kp = open_db(source, key_file)
    kp.save(str(control))
    _, control_flat = load_flat(control, key_file)
    control_bad = print_rows("%s — контроль (pykeepass → pykeepass)" % source.name,
                             diff(before, control_flat), False)
    if control_bad:
        print("  !! оракул врёт: нормализация даёт отличия там, где их нет")
        return control_bad

    target = workdir / ("core_" + source.name)
    resave_with_core(source, target, key_file)
    _, after = load_flat(target, key_file)
    return print_rows("%s — наше ядро" % source.name, diff(before, after), show_all, labels)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    show_all = "--all" in sys.argv
    fixtures = args or DEFAULT_FIXTURES

    workdir = Path(tempfile.mkdtemp(prefix="okp_compare_"))
    try:
        bad = sum(compare_fixture(f, show_all, workdir) for f in fixtures)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    print("\nИтог: %s" % ("отличий нет" if bad == 0 else "%d отличий" % bad))
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
