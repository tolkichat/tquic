# Tarantino Architecture: Best-of-Breed Async QUIC Adapter

**Подход:** Разбить async QUIC adapter на подзадачи, найти кто решил каждую лучше всех, забрать лучшие кусочки, собрать вместе.

---

## Текущее состояние

| Метрика (1MB stream) | Оригинал tquic | Наш reactor | Quinn | s2n-quic | Цель |
|---|---|---|---|---|---|
| **Время** | 5.36ms | ~25ms | 16.3ms | 17.4ms | <7ms |
| **Context switches / write** | 0 | 2 | 0 | 0 | 0 |
| **Overhead vs оригинал** | 1x | 4.7x | 3x | 3.2x | <1.3x |

---

## Декомпозиция: подзадачи async QUIC adapter

### 1. Stream Write (user → QUIC engine)

**Кто решил лучше: Quinn**

| Библиотека | Паттерн | Switches | Копий данных |
|---|---|---|---|
| Quinn | `std::sync::Mutex` + прямой `proto::SendStream::write()` | 0 | 1 (в proto buffer) |
| s2n-quic | `Lock` trait (Mutex) + прямой `poll_stream_request()` | 0 | 1 |
| Cloudflare | Callback `process_writes(&mut qconn)` | 0 | 1 |
| **Наш** | **Slot → Notify → reactor → stream_send()** | **2** | **2** |

**Что берём:** Direct call pattern. User task вызывает `stream_send()` напрямую.

**Адаптация для !Send tquic:** Вместо `Arc<Mutex<>>` используем `Rc<RefCell<>>` — всё на одном `LocalSet` потоке.

```rust
// Quinn (reference):
fn poll_write(cx, buf) -> Poll<Result<usize>> {
    let state = self.conn.state.lock();                    // std::sync::Mutex
    let stream = state.inner.send_stream(self.stream_id);
    match stream.write(buf) {
        Ok(n) => { state.wake(); Poll::Ready(Ok(n)) }
        Err(Blocked) => { state.blocked_writers.insert(id, cx.waker()); Poll::Pending }
    }
}

// Наша адаптация:
fn poll_write(cx, buf) -> Poll<Result<usize>> {
    let mut inner = self.inner.borrow_mut();               // Rc<RefCell<>>
    match inner.connection.stream_send(self.stream_id, buf, false) {
        Ok(n) => { inner.mark_sendable(); Poll::Ready(Ok(n)) }
        Err(Error::Done) => { inner.register_write_waker(self.stream_id, cx.waker()); Poll::Pending }
    }
}
```

**Статус:** [ ] Не начато

---

### 2. Stream Read (QUIC engine → user)

**Кто решил лучше: Quinn**

| Библиотека | Паттерн | Switches |
|---|---|---|
| Quinn | `Mutex` + прямой `proto::RecvStream::read()` | 0 |
| s2n-quic | `Lock` + прямой `poll_stream_request()` | 0 |
| **Наш** | **Slot → Notify → reactor → stream_read()** | **2** |

**Что берём:** Direct call. Аналогично write.

```rust
// Наша адаптация:
fn poll_read(cx, buf) -> Poll<Result<(usize, bool)>> {
    let mut inner = self.inner.borrow_mut();
    match inner.connection.stream_read(self.stream_id, buf) {
        Ok((n, fin)) => Poll::Ready(Ok((n, fin))),
        Err(Error::Done) => { inner.register_read_waker(self.stream_id, cx.waker()); Poll::Pending }
    }
}
```

**Статус:** [ ] Не начато

---

### 3. Flow Control Wakeups

**Кто решил лучше: s2n-quic**

| Библиотека | Хранение wakers | Поиск | Аллокации |
|---|---|---|---|
| Quinn | `FxHashMap<StreamId, Waker>` на Connection | O(1) lookup | HashMap entry |
| **s2n-quic** | **Waker прямо на struct потока** | **O(1) прямой доступ** | **Zero** |
| Cloudflare | Callback-driven (нет wakers) | N/A | N/A |
| Наш | `on_stream_writable` → retry slot | O(1) HashMap | Arc<StreamSlot> |

**Что берём:** Waker на struct потока (s2n-quic pattern).

```rust
// s2n-quic pattern:
struct StreamState {
    write_waker: Option<Waker>,
    read_waker: Option<Waker>,
}

// on_stream_writable callback:
fn on_stream_writable(&mut self, stream_id: u64) {
    if let Some(state) = self.streams.get_mut(&stream_id) {
        if let Some(waker) = state.write_waker.take() {
            waker.wake();  // прямой wakeup, zero overhead
        }
    }
}
```

**Статус:** [ ] Не начато

---

### 4. UDP Recv Loop

**Кто решил лучше: s2n-quic (GSO/GRO batching)**

| Библиотека | Паттерн | Batching |
|---|---|---|
| Quinn | `tokio::UdpSocket::recv_from` в select! | По 1 пакету |
| **s2n-quic** | **GSO/GRO + `recvmmsg()`** | **До 64 пакетов за syscall** |
| Cloudflare | `tokio::UdpSocket::recv_from` | По 1 пакету |
| Наш | `tokio::UdpSocket::recv_from` + `drain_udp_recv` | Drain loop |

**Что берём:** Пока оставляем наш drain loop (достаточно для localhost). GSO/GRO — оптимизация для production с реальной сетью.

**Статус:** [x] Текущий подход достаточен

---

### 5. Packet Sending

**Кто решил лучше: s2n-quic (GSO sendmsg batching)**

| Библиотека | Паттерн |
|---|---|
| Quinn | `poll_transmit()` → `UdpSender::poll_send()` (по 1) |
| **s2n-quic** | **GSO `sendmsg()` до 64 пакетов за syscall** |
| Наш | `process_and_dispatch()` → батч `send_to()` |

**Что берём:** Пока оставляем наш batching. GSO — для production.

**Статус:** [x] Текущий подход достаточен

---

### 6. Timer Management

**Все решают одинаково:** `tokio::time::sleep` + reset.

**Статус:** [x] Текущий подход достаточен

---

### 7. Connection Lifecycle (handshake, close)

**Все решают одинаково:** Отдельная task/driver для lifecycle events.

**Что берём:** Оставляем наш подход с control commands через mpsc channel. Это cold path — оптимизация не нужна.

**Статус:** [x] Текущий подход достаточен

---

## Итоговая архитектура: "Tarantino Cut"

```
                    ВСЁ НА ОДНОМ ПОТОКЕ (LocalSet)
    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │  TquicInner (Rc<RefCell<>>)              ← от Cloudflare    │
    │  ├── connection: Connection               (single-owner)    │
    │  ├── endpoint: Endpoint                                     │
    │  ├── streams: HashMap<u64, StreamState>                     │
    │  │   └── StreamState {                    ← от s2n-quic     │
    │  │       write_waker: Option<Waker>,       (waker на struct)│
    │  │       read_waker: Option<Waker>,                         │
    │  │   }                                                      │
    │  └── driver_waker: Option<Waker>                            │
    │                                                              │
    │  SendStream {                             ← от Quinn        │
    │    inner: Rc<RefCell<TquicInner>>,          (direct call)   │
    │    stream_id: u64,                                          │
    │  }                                                          │
    │  write(buf) → inner.borrow_mut().stream_send(id, buf)       │
    │                                                              │
    │  RecvStream {                             ← от Quinn        │
    │    inner: Rc<RefCell<TquicInner>>,          (direct call)   │
    │    stream_id: u64,                                          │
    │  }                                                          │
    │  read(buf) → inner.borrow_mut().stream_read(id, buf)        │
    │                                                              │
    │  Driver loop (select!):                   ← наш (уже хорош) │
    │    UDP recv → inner.borrow_mut().endpoint.recv()             │
    │    timer → inner.borrow_mut().endpoint.on_timeout()          │
    │    process_and_dispatch()                                    │
    │    for stream in writable:                ← от Quinn        │
    │      if let Some(waker) = state.write_waker.take() {        │
    │        waker.wake();                       (waker pattern)  │
    │      }                                                      │
    │                                                              │
    │  Control commands (mpsc):                 ← наш (cold path) │
    │    OpenBi, OpenUni, Close, Stats                            │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘
```

---

## Ключевое ограничение: tquic `!Send`

tquic Connection использует `Rc<RefCell<>>` внутри → не может быть в `Arc<Mutex<>>`.

**Решение:** Всё на одном `LocalSet` потоке:
- `Rc<RefCell<TquicInner>>` безопасен (один поток)
- Никакого `unsafe`
- Stream handles работают на том же `LocalSet`
- Внешние tasks общаются через channel → spawn_local обрабатывает

---

## План реализации

### Phase 1: TquicInner shared state
- [ ] Создать `TquicInner` struct с `connection`, `endpoint`, `streams` HashMap
- [ ] Обернуть в `Rc<RefCell<>>`
- [ ] StreamState с write_waker/read_waker
- **Файлы:** новый `inner.rs`

### Phase 2: Direct-call SendStream/RecvStream
- [ ] Новый `SendStream` с `Rc<RefCell<TquicInner>>` + `poll_fn` based write
- [ ] Новый `RecvStream` с `poll_fn` based read
- [ ] Прямой вызов `stream_send()`/`stream_read()` через `borrow_mut()`
- **Файлы:** заменить `fast_stream.rs`

### Phase 3: Driver loop refactor
- [ ] Driver loop делает `borrow_mut()` для UDP recv, timers, packet sending
- [ ] `on_stream_writable` → wake stored waker
- [ ] `on_stream_readable` → wake stored waker
- [ ] Control commands (open/close) остаются через mpsc
- **Файлы:** рефакторить `reactor.rs`

### Phase 4: Wire up + benchmark
- [ ] Собрать всё вместе
- [ ] Интеграционные тесты (3/3 должны пройти)
- [ ] Benchmark: target <7ms для 1MB stream

---

## Прогресс

| Подзадача | Источник | Статус | Результат |
|---|---|---|---|
| Stream write (direct call) | Quinn | TODO | |
| Stream read (direct call) | Quinn | TODO | |
| Flow control wakeups | s2n-quic | TODO | |
| Single-owner state | Cloudflare | TODO | |
| UDP recv loop | Наш (drain) | Done | Достаточен |
| Packet sending | Наш (batch) | Done | Достаточен |
| Timer management | Наш (tokio::time) | Done | Достаточен |
| Connection lifecycle | Наш (mpsc) | Done | Достаточен |

---

## Ссылки

- Quinn `SendStream::write`: `quinn/src/send_stream.rs:60` → `execute_poll()` → `Mutex::lock()` → `proto::SendStream::write()`
- Quinn `ConnectionDriver`: `quinn/src/connection.rs:244` — driver task для UDP I/O
- s2n-quic `Lock` trait: `quic/s2n-quic-transport/src/connection/connection_trait.rs:551`
- s2n-quic waker на struct: `quic/s2n-quic-transport/src/stream/api.rs`
- Cloudflare `ApplicationOverQuic`: `tokio-quiche/src/quic/connection/mod.rs:721`
- Наш reactor loop: `src/tokio_adapter/reactor.rs:249` — `select!` loop
- Performance roadmap: `docs/performance-roadmap.md`
