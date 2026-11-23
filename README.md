# FlashDeHash (Rust)

Высокопроизводительная реализация **FlashDeHash** на Rust — движок мгновенного восстановления строк по хешу на базе предварительно отсортированных бинарных словарей единого формата `.fdh`.

## Ключевые улучшения относительно Java-версии

- **Единый файл `.fdh`** (выровненный по 4 КиБ заголовок + последовательные отсортированные чанки) вместо папки с сотнями файлов `chunk_*.bin` и `metadata.json`.
- **Догенерация (append)** новых чанков в конец существующего `.fdh` с атомарным обновлением `chunk_count` в заголовке (безопасно при прерывании).
- **Низкое потребление RAM при генерации**: ~264 МиБ RSS на чанк $2^{24}$ (in-place 256-way American Flag MSD Radix Sort + параллельная сортировка бакетов) вместо 4–6 ГиБ в Java.
- **Контроль нагрузки**: по умолчанию используется ~75% логических ядер CPU, чтобы система не лагала и не тротлила (`--threads` для переопределения).
- **Zero-copy `mmap` поиск** с интерполяционным предсказанием (`target[0..3] ± 8192`) и **100% точным boundary fallback** (нулевой оверхед в 99.994% запросов, 100% recall на хвостах $>4\sigma$).
- **Защита от дурака для алфавита**: при генерации новых словарей пробел `' '` гарантированно ставится на индекс `0` (с удалением дубликатов), а при конвертации старых словарей исходный алфавит сохраняется побитово с флагом `LEGACY`.
- **Мгновенный конвертер старых словарей** (`fdh convert`): склеивает `chunk_*.bin` без перехеширования, игнорирует macOS `._*` файлы и автоматически распознаёт старую Java-заглушку `CSHAKE128` (`SHA3-256`).
- **Модульная система хеш-функций**: добавление нового алгоритма — реализация трейта `Hasher` (5–10 строк) + 1 строка регистрации в `HashRegistry`.

## Замеры (Apple Silicon, 6 потоков, `--release`)

- Генерация 1 чанка SHA-256 ($2^{24} = 16\,777\,216$ записей, 48 МиБ): **1.57 сек** (hash 1.08s + sort 0.45s + write 45ms), пик RAM **264 МиБ**.
- Поиск (1 чанк, 16.7M записей): **0.008 мс/хеш** (~130k хешей/сек), recall **100%**.
- Поиск (4 реальных конвертированных чанка SHA-256, 67.1M записей): **0.041 мс/хеш** (~24k хешей/сек), recall **100%**.

## Сборка и запуск

```bash
# Сборка CLI и GUI в release
cargo build --release

# Список поддерживаемых хеш-функций
./target/release/fdh algos

# Генерация нового словаря (пробел автоматически гарантируется в начале алфавита)
./target/release/fdh generate --algo SHA256 --alphabet "0123456789" --chunks 4 --output dict.fdh

# Догенерация чанков в существующий словарь
./target/release/fdh append --dict dict.fdh --chunks 4

# Конвертация старой Java-папки в единый .fdh
./target/release/fdh convert --input "/Volumes/Netac ExFAT/FlashDeHash/chuncks_SHA256_[0-9]" --output sha256_digits.fdh

# Поиск (одиночный или интерактивный REPL, если не передавать хеш)
./target/release/fdh search --dict dict.fdh <HEX_HASH>
./target/release/fdh search --dict dict.fdh

# Информация и бенчмарк
./target/release/fdh info dict.fdh
./target/release/fdh bench --dict dict.fdh --count 500

# Слияние 3-байтных чанков (степень двойки 2..=256) в один 4-байтный чанк
./target/release/fdh merge --input dict_3b.fdh --output dict_4b.fdh

# Обработка текстового словаря (customChunk)
./target/release/fdh custom-dict --input passwords.txt --output-dir out_chunks/

# Запуск Telegram-бота
./target/release/fdh bot --dict dict.fdh --config bot_config.json

# Запуск нативного GUI
./target/release/fdh-gui
```

## Добавление новой хеш-функции

1. Добавьте структуру, реализующую `Hasher`, в `crates/fdh-core/src/hash/algorithms.rs`.
2. Зарегистрируйте её одной строкой `reg.register(Arc::new(...))` в `HashRegistry::with_builtins()` в `crates/fdh-core/src/hash/mod.rs`.
