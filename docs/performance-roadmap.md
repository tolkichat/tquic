# Roadmap: Производительность tokio-reactor адаптера

**Цель:** Приблизить скорость `tokio-reactor` адаптера к оригинальной tquic sans-I/O библиотеке.

---

## Текущее состояние

| Метрика (1MB stream) | Оригинал tquic 1.6.0 | Наш tokio-reactor | Quinn (референс) | Цель |
|---|---|---|---|---|
| **Время** | 5.36ms | ~24ms | 16.3ms | <10ms |
| **Пропускная способность** | 186 MiB/s | 45 MiB/s | 61 MiB/s | >100 MiB/s |
| **Overhead vs оригинал** | 1x | 4.5x | 3x | <2x |

---

## Диагностика: почему 4.5x overhead?

### Что мы уже исправили (Round 5-6)

| Проблема | Решение | Эффект |
|---|---|---|
| 456 `oneshot::channel()` аллокаций на 1MB | Заменили на `StreamSlot` (pre-allocated, reusable) | Убрали все heap-аллокации на data path |
| Двойное копирование при read (temp Vec -> user buf) | Zero-copy read: reactor пишет напрямую в user buffer через raw pointer | Убрали 200 лишних memcpy |
| Одиночная запись в reactor per slot wakeup | Drain loop: reactor пишет в tight loop до flow-control block | **64KB улучшилось в 4x** (21.8ms -> 5.26ms) |

### Что осталось: per-chunk async round-trips

**Главная проблема:** `write_all()` в `fast_stream.rs` вызывает `write()` в цикле, каждый вызов:
1. `Bytes::copy_from_slice(buf[offset..])` - аллокация + копирование
2. `slot.set_write()` -> `reactor_notify.notify_one()` - context switch #1
3. Reactor обрабатывает -> `slot.done_notify.notify_one()` - context switch #2
4. User task просыпается, проверяет результат

Для 1MB с 4KB чанками = **256 round-trips x 2 context switches = 512 переключений**.

**Drain loop помог для 64KB** (16 чанков -> drain loop обрабатывает все за 1 wakeup), но для 1MB flow-control блокирует после ~64KB, и цикл `write_all` снова начинает per-chunk round-trips.

---

## План оптимизации (по приоритету)

### Step 1: Bulk write - одна операция на весь буфер
**Статус:** Следующий шаг
**Ожидаемый эффект:** Очень высокий (256 round-trips -> 1)

**Идея:** `write_all()` отправляет ВЕСЬ буфер (1MB `Bytes`) в slot за один раз. Reactor дренирует его через множество `on_stream_writable` callback'ов, без возврата к user task.

```
Сейчас (per-chunk):
  write_all(1MB):
    write(4KB) -> slot -> reactor -> done -> write(4KB) -> slot -> reactor -> done -> ... x256

После (bulk):
  write_all(1MB):
    slot.set_write(Bytes(1MB), fin) -> reactor_notify
    reactor: drain_slot_write loop:
      stream_write(chunk) -> Ok(4KB) -> stream_write(next) -> ...
      flow_control_block -> park remaining in slot
    on_stream_writable -> drain_slot_write continues
    ... repeat until all 1MB drained
    slot.done_notify -> user gets Ok(1MB)
```

**Изменения:**
- `fast_stream.rs`: `write_all()` вызывает `write()` один раз с полным буфером
- `slot.rs`: `WriteRequest.total_len` уже отслеживает оригинальный размер (готово!)
- `reactor.rs`: `drain_slot_write` уже обрабатывает partial writes с `re_park_write` (готово!)
- Единственное изменение: `write_all` -> single `write(full_buf)` + reactor drains across `on_stream_writable`

**Риск:** Low. Инфраструктура уже на месте (drain loop + re_park_write + total_len tracking).

### Step 2: Bulk read - reactor дренирует весь доступный поток
**Статус:** Планируется
**Ожидаемый эффект:** Высокий

**Идея:** Аналогично write - reactor читает в tight loop до `Error::Done`, заполняя user buffer максимально.

```
Сейчас:
  read(buf[65536]) -> slot -> reactor -> stream_read(buf, 65536) -> Ok(4096) -> done

После:
  read(buf[65536]) -> slot -> reactor:
    stream_read(buf[0..], 65536) -> Ok(4096)
    stream_read(buf[4096..], 61440) -> Ok(4096)
    ... loop until Error::Done or buf full
    done_notify(total_read)
```

**Изменения:**
- `reactor.rs`: `execute_slot_read()` -> tight loop до Error::Done или buffer full

### Step 3: Pre-established benchmark (отделить handshake от data path)
**Статус:** Планируется
**Ожидаемый эффект:** Высокий для диагностики

Текущий benchmark включает handshake (~3ms) в каждую итерацию stream throughput. Это маскирует реальный overhead data path.

**Добавить:**
- `stream_throughput_warm/1MB` - с pre-established connection
- Позволит точно измерить overhead чисто data path

### Step 4: Readiness-based API (не будить reactor на каждый чанк)
**Статус:** Исследование
**Ожидаемый эффект:** Высокий

**Идея из Codex:** Вместо "submit write -> wake reactor -> wait for done" на каждый chunk:
- `write()` ставит данные в очередь и возвращается сразу (если очередь не полна)
- Reactor дренирует очередь когда просыпается (по таймеру или socket ready)
- `write()` await'ит только когда очередь полна (backpressure)

Это как TCP write buffer - user пишет быстро, kernel (reactor) дренирует асинхронно.

**Сложность:** Высокая. Меняет API семантику (write может "успешно" вернуться до реальной отправки).

### Step 5: Увеличить chunk size в benchmark (32-64KB вместо 4KB)
**Статус:** Можно сделать сразу
**Ожидаемый эффект:** Средний

4KB чанки усиливают per-chunk overhead. В реальном use case (аудио) чанки 160-320 байт (20-40ms Opus), но для benchmark throughput 32-64KB ближе к реальности bulk transfers.

### Step 6: Quinn-style direct-call model (lock-based)
**Статус:** Исследование
**Ожидаемый эффект:** Средне-высокий, сложность: высокая

Quinn использует `Mutex<ConnectionInner>` + прямой вызов `stream_write` без reactor. User task берет lock, вызывает `poll_fn` с прямым доступом к connection, отпускает lock.

Для tquic это сложно, потому что tquic types are `!Send` (Rc<RefCell>). Но возможен гибридный подход: reactor thread принимает "batch" операций и выполняет их за один wakeup.

---

## Архитектурные заметки

### Почему оригинал такой быстрый? (из анализа /src/tquic-original)

Оригинальный tquic (sans-I/O + mio) — **zero overhead data path**:

1. **Синхронный mio event loop** — `Poll::poll()` -> `endpoint.recv()` -> `process_connections()` -> `send_packets_out()` в одном цикле
2. **Прямые вызовы** — app вызывает `conn.stream_write(id, buf, fin)`, данные сразу попадают в `SendBuf` (VecDeque\<RangeBuf\>)
3. **Callback-driven** — `on_stream_readable()` вызывается прямо в `process_connections()`, app сразу читает
4. **Zero-copy** — `RangeBuf` оборачивает `Bytes` (ref-counted), `split_to()`/`advance()` двигают указатели без копирования
5. **Batched packets** — `PacketQueue` собирает до 1024 пакетов, один `sendmsg()` syscall
6. **Rc\<RefCell\>** вместо Arc — нет атомарных операций
7. **FxHashSet** для tickable/sendable connections — O(1) insert/remove

Ключевой паттерн: **данные никогда не покидают поток** — от `stream_write()` через `RangeBuf` в `send()` до `sendmsg()` всё в одном потоке без каналов.

### Наш reactor: что добавляет overhead

1. **tokio runtime** (~1.1-1.6x) — executor, task scheduling, wakers
2. **Per-chunk async round-trips** (главный bottleneck) — 256 round-trips x 2 context switches для 1MB
3. **Arc\<StreamSlot\> atomics** (минимальный) — ~0.1ms на 1MB
4. **Bytes::copy_from_slice** — копия данных в каждом `write()` вызове
5. **Отсутствие batching** — каждая операция обрабатывается отдельно

### Что можно перенять у оригинала

| Паттерн оригинала | Как адаптировать для reactor |
|---|---|
| Прямой `stream_write()` без каналов | Bulk write: один slot submit на весь буфер, reactor дренирует |
| Callback `on_stream_readable()` с немедленным чтением | Bulk read: reactor читает в tight loop до Error::Done |
| `SendBuf` (VecDeque\<RangeBuf\>) буферизация | Per-stream TX queue — app складывает, reactor дренирует |
| Batched `send_packets_out()` | Reactor уже батчит (process_and_dispatch), но можно агрессивнее |
| `RangeBuf` zero-copy в `Bytes` | Использовать `Bytes::from(buf)` без copy_from_slice |
| Один поток = нет context switches | Минимизировать switches: 1 per flow-control window вместо 1 per chunk |

### Рекомендации Codex (Round 2)

1. **Bulk `write_all` — правильный следующий шаг**. Pitfalls: cancellation, stream fairness budget, memory pressure
2. **`write()` оставить как partial-write**, оптимизировать только `write_all()`
3. **Near-zero context switches** невозможны между tasks, но можно амортизировать (1 handoff per flow-control window)
4. **Readiness-driven API** (`poll_write`/`poll_read`) + wake только на state transitions (empty->nonempty, full->has_space)
5. **Per-stream TX/RX buffers** — reactor дренирует/заполняет непрерывно
6. **Поднять stream flow-control windows** — уменьшить wake cycles per MB
7. **Fairness budgets** — per-stream byte/time budget в reactor

### Теоретический минимум для reactor

Если убрать per-chunk round-trips (Steps 1-2), overhead = только:
- tokio event loop vs mio (~1.1-1.6x)
- Atomic operations на slot state machine (~0.1ms на 1MB)
- ~16 Notify wakeups per 1MB (1 per 64KB flow-control window) вместо 256

**Теоретический target: 6-9ms для 1MB** (1.1-1.7x overhead vs 5.36ms).

Codex подтверждает: если реализовать Steps 1-4, sub-10ms реалистично на localhost.

### Сравнение с Quinn

Quinn достигает 16.3ms при использовании `Mutex<ConnectionInner>` + `poll_fn`. Наш reactor pattern потенциально быстрее Quinn, т.к.:
- Нет lock contention (single-owner reactor)
- Batching через drain loops
- Zero-copy reads (Quinn копирует в промежуточный RecvBuf)

---

## Прогресс

| Step | Описание | Статус | Результат |
|---|---|---|---|
| Slot infrastructure | StreamSlot + fast_stream (Phase 1-3) | Done | Все тесты проходят, dead code удален |
| Drain loop (reactor) | Tight loop в execute_slot_write/read | Done | 64KB: 21.8ms -> 5.26ms (4x!), 1MB: без изменений |
| Step 1: Bulk write | Одна slot операция на весь буфер | **Done** | 64KB: 13.8ms -> **4.5ms (3x!)**, 1MB: 23.6ms -> **21ms (12%)** |
| Step 2: Bulk read | Drain loop для read | **Done** | Минимальный эффект: read path уже использовал 64KB буфер (~16 round-trips на 1MB). Код корректен, тесты проходят. |
| Step 3: Warm benchmark | Pre-established connection | TODO | |
| Step 4: Readiness API | Queue-based write/read | Research | |
| Step 5: Chunk size | 32-64KB в benchmark | TODO | |
| Step 6: Direct-call | Quinn-style lock model | Research | |

---

## Ссылки

- **Codex Round 1**: диагностика per-chunk bottleneck, queue + readiness рекомендации
- **Codex Round 2**: подтверждение bulk write плана, fairness budgets, flow-control windows
- **Explorer agent**: детальный анализ оригинала (/src/tquic-original), saved as memory #1487
- tquic оригинал: `src/connection/stream/mod.rs` — stream_write flow control, SendBuf = VecDeque\<RangeBuf\>
- tquic оригинал: `tools/src/bin/tquic_client.rs` — mio event loop, process_connections()
- Quinn: `quinn-proto/src/connection/streams/send.rs` — poll_fn + Mutex pattern
- s2n-quic: tokio-native, GSO, zero-copy paths
