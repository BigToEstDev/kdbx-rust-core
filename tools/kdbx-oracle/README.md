# kdbx-oracle

Независимая реализация KDBX4 (`pykeepass`, Python) как **эталон** для тестов Rust-ядра.

Зачем: наши тесты исторически проверяли только round-trip собственной реализации. Если она симметрично
«неправильная» (не тот режим CBC, не тот counter у ChaCha20, не тот вариант Argon2), тесты остаются
зелёными, а файл не открывается ни в одном настоящем KeePass. Файлы, собранные чужим кодом, закрывают
эту дыру.

**Только dev-инструмент.** В поставку приложения не попадает: Python на Android не даёт контроля над
памятью (секреты нельзя затирать), а `pycryptodome`/`argon2-cffi`/`lxml` — C-расширения под каждый ABI.
Ядро приложения — Rust.

## Установка

```bash
cd D:/MyDev/StartUp/passholder/pass-rust-core
python -m venv .venv
.venv/Scripts/python.exe -m pip install --only-binary=:all: -r tools/kdbx-oracle/requirements.txt
```

`--only-binary=:all:` обязателен: без него pip при отсутствии wheel начнёт собирать `lxml` /
`pycryptodomex` / `argon2-cffi` через MSVC. На Python 3.14.2 все wheel'ы есть.

`.venv/` в git не попадает (`python -m venv` кладёт внутрь свой `.gitignore` с `*`).

## Скрипты

| Скрипт | Зависимости | Что делает |
|---|---|---|
| `dump_header.py` | нет (stdlib) | Печатает outer header `.kdbx`: версию формата, шифр, KDF и его параметры. Первое, чем стоит проверять «почему core не читает этот файл». |
| `gen_fixtures.py` | pykeepass | Генерирует фикстуры в `crates/kdbx-rust-core/tests/resources/`. Запускать только при осознанной перегенерации. |
| `verify_roundtrip.py` | pykeepass | Проверяет, что база, записанная нашим core, читается сторонней реализацией. Отдельная CI-job после `cargo test`. |

```bash
.venv/Scripts/python.exe tools/kdbx-oracle/dump_header.py crates/kdbx-rust-core/tests/resources/aes256_argon2d.kdbx
.venv/Scripts/python.exe tools/kdbx-oracle/gen_fixtures.py
.venv/Scripts/python.exe tools/kdbx-oracle/verify_roundtrip.py
```

## Правило: Python не в пути `cargo test`

Фикстуры генерируются один раз и **коммитятся** в `crates/kdbx-rust-core/tests/resources/`. Rust-тесты читают готовые файлы,
поэтому `cargo test` работает без Python, офлайн и в CI. Обратная проверка (`verify_roundtrip.py`) —
отдельный шаг, а не `#[ignore]`-тест: от `#[ignore]` в проекте избавились осознанно.

## Фикстуры

Пароль всех баз: `test-pass-1234`. Данные фейковые.

| Файл | Шифр | KDF | Argon2 |
|---|---|---|---|
| `aes256_argon2d.kdbx` | AES-256/CBC | Argon2d | 16 MB / 2 iter / P=2 |
| `chacha20_argon2id.kdbx` | ChaCha20 | Argon2id | 16 MB / 2 iter / P=2 |
| `aes256_argon2d_keyfile.kdbx` + `.keyx` | AES-256/CBC | Argon2d | 16 MB / 2 iter / P=2 |
| `aes256_argon2d_prod_params.kdbx` | AES-256/CBC | Argon2d | 64 MB / 10 iter / P=2 |

**Слияние и импорт (Step 106)** — `build_merge_fixtures`: `merge_base.kdbx` (пароль общий), её копия
`merge_copy.kdbx` с паролем `copy-pass-5678` (правка `Edited` с версией, удаление `Deleted` с `DeletedObject`,
новая `Added` — позже всего в исходной) и другая база `merge_other.kdbx` с паролем `other-pass-9012` и своим
корнем (шаблон pykeepass даёт всем новым базам **один UUID корня** — задаём явно). Читает
`tests/merge_from_bytes.rs`; слитую нашим ядром базу проверяет `verify_roundtrip.py` (`written_merged.kdbx`).
Перегенерировать только их, не трогая остальные:
`.venv/Scripts/python.exe -I -c "import sys; sys.path.insert(0,'tools/kdbx-oracle'); import gen_fixtures as g; g.build_merge_fixtures()"`.

**Key-файлы всех форматов (Step 113)** — `build_key_file_format_fixtures`: по базе на формат, key-файл рядом —
`key_file_raw32` (ровно 32 байта), `key_file_hex64` (64 hex), `key_file_xml_v1` (XML 1.0, base64),
`key_file_xml_no_decl` (XML 2.0 без `<?xml`), `key_file_xml_other` (XML не `<KeyFile>` — хешируется). Разбор
pykeepass совпадает с KeePassXC. Читает `tests/key_file_formats.rs`. Только их:
`.venv/Scripts/python.exe -I -c "import sys; sys.path.insert(0,'tools/kdbx-oracle'); import gen_fixtures as g; g.build_key_file_format_fixtures()"`.
Байты фикстур git не трогает: `tests/resources/** binary` в `.gitattributes` (иначе `core.autocrlf` меняет ключ).

Параметры Argon2 занижены намеренно: каждый тест платит за KDF при открытии базы. Отдельная фикстура с
боевыми параметрами проверяет, что и такие читаются.

Содержимое одинаковое во всех базах, чтобы Rust-тесты были общими: записи `GitHub`, `Email` в корне;
подгруппа `Work` с записью `Server`, у которой заполнены notes, TOTP (`entry.otp`) и аттачмент
`notes.txt`. Покрывает protected-значения (inner-stream ChaCha20), binaries и вложенность групп.

Key-file — XML KeyFile v2 (`<Data>` = 32 байта ключа в hex, `Hash` = первые 4 байта SHA-256 от них),
тот формат, что пишет наше ядро; остальные форматы key-файлов, что читает `src/db/file_key.rs`, — фикстуры
Step 113 выше.

## Грабли pykeepass

- `create_database()` не принимает cipher/KDF — они правятся через `construct`-структуры
  (`kp.kdbx.header.value.dynamic_header`), см. `gen_fixtures.py`.
- Правки header применяются **только при `kp.save()`**; до этого на диске лежит шаблон пакета
  (KDBX 4.0, AES-256, Argon2d, 64 MB / 14 iter).
- TOTP задаётся только через `entry.otp` — ключ `otp` зарезервирован, `set_custom_property('otp', ...)`
  падает с `AssertionError`.
- `M` (память Argon2) — в байтах.
- Длина IV зависит от шифра: AES/Twofish — 16 байт, ChaCha20 — 12.

## Чего наш core НЕ читает

Частая причина «фикстура не подошла»:

- **KDBX 3.x** — `db/reader_writer.rs:80-85`, `Error::OldUnsupportedKdbxFormat`. В KeePassXC выбор
  **KDF = AES** (AES-KDF) заставляет писать KDBX 3.1. Для KDBX4 нужен KDF = Argon2d/Argon2id.
- **Twofish** — `constants.rs:411-415`, только AES256 и ChaCha20 → `Error::UnsupportedCipher`.
- **AES-KDF** — закомментирован (`constants.rs:406`) → `Error::SupportedOnlyArgon2dKdfAlgorithm`.
- **Salsa20 inner stream** — поддерживается только ChaCha20 (`constants.rs:484`).
