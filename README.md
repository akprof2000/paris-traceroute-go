# paris-traceroute-go

Реализация [Paris Traceroute](https://paris-traceroute.net/) на Go: трассировка
маршрута, которая не искажается балансировщиками нагрузки, и алгоритм MDA для
поиска всех балансируемых путей. Один статически собранный бинарник для Linux
и Windows, без зависимостей от libpcap и C-библиотек.

*A Go implementation of Paris Traceroute (fixed flow-id tracing) and the
Multipath Detection Algorithm, for Linux and Windows.*

## Зачем

Обычный traceroute меняет в каждом пробе поля, по которым маршрутизаторы
распределяют потоки (порты UDP, идентификатор ICMP), поэтому разные пробы
идут разными путями. Результат — несуществующие связи между узлами, петли и
«ромбы». Paris traceroute держит постоянным *идентификатор потока* (все поля,
которые может хешировать балансировщик) и метит пробы в полях, которые
балансировщики не смотрят:

| Протокол | Постоянно (flow-id)                     | Метка пробы                                  |
|----------|------------------------------------------|----------------------------------------------|
| UDP      | адреса, порты, длина                     | контрольная сумма UDP (подгоняется 2 байтами нагрузки) |
| ICMP     | тип, код, контрольная сумма              | sequence; identifier компенсирует сумму      |
| TCP      | адреса, порты                            | старшие 16 бит sequence number               |

**MDA** (Multipath Detection Algorithm, Augustin et al.) перебирает разные
flow-id и на каждом хопе посылает столько проб, чтобы с заданной
достоверностью (по умолчанию 95%) найти все следующие интерфейсы каждого
узла. Результат — граф балансируемых путей.

## Установка

Готовые архивы — на странице [Releases](https://github.com/akprof2000/paris-traceroute-go/releases):

- Linux: `paris-traceroute_<версия>_linux_amd64.tar.gz` (и `arm64`)
- Windows: `paris-traceroute_<версия>_windows_amd64.zip` (и `arm64`)

Или из исходников (Go 1.27+):

```sh
go install github.com/akprof2000/paris-traceroute-go/cmd/paris-traceroute@latest
```

## Права

Утилита работает через raw-сокеты:

- **Linux** — от root или с capability:
  `sudo setcap cap_net_raw+ep ./paris-traceroute`
- **Windows** — из консоли, запущенной от имени администратора. Среди
  стандартных правил брандмауэра Windows нет разрешения для входящих ICMPv4
  «Time Exceeded», без них промежуточные хопы будут `*`. Разрешить
  (PowerShell от администратора):

  ```powershell
  New-NetFirewallRule -DisplayName "paris-traceroute ICMPv4" -Direction Inbound -Protocol ICMPv4 -IcmpType 11,3 -Action Allow
  New-NetFirewallRule -DisplayName "paris-traceroute ICMPv6" -Direction Inbound -Protocol ICMPv6 -IcmpType 3,1 -Action Allow
  ```

  TCP-пробы на Windows недоступны: система запрещает отправку TCP через
  raw-сокеты. Используйте `-P udp` или `-P icmp`. До 127.0.0.1 работает только
  ICMP: на loopback Windows не отвечает ICMP port unreachable.

## Использование

```
paris-traceroute [опции] хост
```

| Опция | Описание |
|-------|----------|
| `-a, --algorithm paris\|mda` | алгоритм: `paris` (фиксированный поток, по умолчанию) или `mda` |
| `-P, --protocol udp\|icmp\|tcp` | протокол проб (по умолчанию `udp`) |
| `-I`, `-T`, `-U` | то же, что `-P icmp`, `-P tcp`, `-P udp -p 53` (как в оригинале) |
| `-4`, `-6` | принудительно IPv4 / IPv6 |
| `-p, --dst-port N` | порт назначения (UDP 33457, TCP 80) |
| `-s, --src-port N` | базовый порт источника, поток f использует N+f |
| `-S, --source ADDR` / `-i, --interface IF` | адрес источника / интерфейс |
| `-F, --flow-id N` | идентификатор потока для `paris` |
| `-f, --first-ttl N`, `-m, --max-ttl N` | первый и максимальный TTL (1 и 30) |
| `-q, --queries N` | проб на хоп для `paris` (3) |
| `-w, --wait SEC` | ожидание ответа, секунды (3) |
| `-M, --max-undiscovered N` | остановка после N подряд молчащих хопов (3) |
| `-z WAIT` | минимальный интервал между пробами: мс, если больше 10, иначе секунды |
| `-t, --timeout SEC` | ограничение времени всего измерения (0 — без ограничения) |
| `-c, --confidence PCT` | достоверность MDA, % (95) |
| `-B, --mda B,BR,CH` | синтаксис оригинала: достоверность, число точек ветвления, максимум соседей (95,5,128) |
| `-r, --retries N` | повторы неотвеченных проб в MDA (2) |
| `--parallel N` | одновременных проб в MDA (16) |
| `-n, --numeric` | не резолвить имена |
| `-j, --json` | вывод в JSON |
| `-V, --version` | версия |

Опции можно указывать и после хоста, как в traceroute.

### Примеры

```sh
sudo paris-traceroute example.com
sudo paris-traceroute -P icmp -n 1.1.1.1
sudo paris-traceroute -P tcp -p 443 example.com
sudo paris-traceroute -6 -P icmp ipv6.google.com
sudo paris-traceroute -a mda -n 8.8.8.8
sudo paris-traceroute -a mda -j 8.8.8.8 > graph.json
```

Вывод `paris` (адреса условные):

```
paris-traceroute to 198.51.100.7 (198.51.100.7) from 192.0.2.10, 30 hops max, udp probes, flow 0
 1  192.0.2.1  0.618 ms  1.078 ms  0.881 ms
 2  203.0.113.1  3.225 ms  3.788 ms  3.353 ms
 3  * 203.0.113.45  7.488 ms  6.095 ms
 4  203.0.113.97  20.608 ms  21.4 ms  20.9 ms [MPLS Label 25156 TC=4 S=1 TTL=1]
 5  198.51.100.7  7.128 ms  7.810 ms  5.392 ms
```

Вывод `mda`: интерфейсы каждого хопа (min/avg/max RTT) и связи между ними:

```
mda to 198.51.100.7 (198.51.100.7) from 192.0.2.10, 30 hops max, udp probes, confidence 95%
 1  192.0.2.1  0.211/1.856/3.399 ms
 2  203.0.113.1  5.683/6.224/6.665 ms
 3  203.0.113.51  5.631/7.386/8.351 ms
    203.0.113.49  5.359/8.016/10.818 ms
    203.0.113.53  6.625/8.154/9.006 ms
 4  198.51.100.7  4.891/6.869/8.440 ms

Links:
 1  192.0.2.1 -> 203.0.113.1
 2  203.0.113.1 -> 203.0.113.51, 203.0.113.49, 203.0.113.53
 3  203.0.113.51 -> 198.51.100.7
 3  203.0.113.49 -> 198.51.100.7
 3  203.0.113.53 -> 198.51.100.7

204 probes sent, destination reached
```

Обозначения: `*` — нет ответа; `!N`, `!H`, `!P`, `!X`, `!F` — сеть/узел/протокол
недостижимы, запрещено администратором, нужна фрагментация; `[MPLS ...]` —
метки из ICMP-расширений (RFC 4950).

## Особенности

- Ответы сопоставляются с пробами по метке, поэтому пробы отправляются
  параллельно; RTT измеряется по каждому пробу.
- Работа за NAT: если NAT пересчитал контрольную сумму UDP в процитированном
  заголовке или не восстановил её, метка восстанавливается по адресу
  источника, по процитированной нагрузке или по порту источника.
- MDA: правило остановки n_k перенесено из оригинала (bound.c, Veitch et al.
  2009): при умолчаниях `-B 95,5,128` n₁..n₅ = 8, 15, 21, 28, 36. Неотвечающие
  пробы повторяются (`-r`), «звёзды» не считаются интерфейсами при расчёте n_k.
- Ответы назначения: UDP — ICMP port unreachable, ICMP — echo reply,
  TCP — SYN/ACK или RST.

## Тесты

```sh
go test ./...                       # юнит-тесты, e2e без прав пропускаются
sudo go test ./...                  # плюс интеграционные тесты на loopback
sudo PT_E2E_HOST=1.1.1.1 go test ./cmd/...   # плюс трассировка реального узла
```

- `internal/packet` — метки и контрольные суммы, разбор ICMP/ICMPv6/TCP, NAT;
- `internal/tracer` — Paris и MDA на симулированной сети с балансировщиками,
  таблица n_k против оригинала;
- `internal/probe` — реальные пробы UDP/ICMP/TCP на 127.0.0.1 и ::1, 64 потока
  параллельно;
- `cmd/paris-traceroute` — разбор опций и e2e-запуски бинарника с проверкой JSON;
- `test/lab/ecmp.sh` — автотест на сети из network namespaces с ECMP-балансировщиком
  (`sudo PT=./paris-traceroute ORIG=/path/to/original test/lab/ecmp.sh` заодно
  сравнивает с оригиналом).

Сравнение с оригинальным paris-traceroute: [docs/COMPARISON.md](docs/COMPARISON.md).

## Сборка

```sh
./build.sh v1.0.0        # Linux/macOS: архивы в dist/
.\build.ps1 -Version v1.0.0 -Test   # Windows
go test ./...
```

Структура:

- `internal/packet` — сборка проб (метки, контрольные суммы) и разбор ответов ICMP/TCP;
- `internal/probe` — raw-сокеты, отправка проб и сопоставление ответов;
- `internal/tracer` — алгоритмы Paris traceroute и MDA;
- `cmd/paris-traceroute` — утилита командной строки.

## Релизы

Релиз собирается GitHub Actions при пуше тега `vX.Y.Z`. После публикации
workflow оставляет только 3 последних релиза: более старые удаляются вместе
с тегами (`scripts/prune-releases.sh`). Артефакты и логи Actions хранятся
1 день (настройка репозитория).

## Ссылки

- B. Augustin et al., *Avoiding traceroute anomalies with Paris traceroute*, IMC 2006.
- B. Augustin, T. Friedman, R. Teixeira, *Measuring load-balanced paths in the Internet*, IMC 2007.
- D. Veitch et al., *Failure control in multipath route tracing*, INFOCOM 2009.
- Оригинальная реализация: [libparistraceroute](https://github.com/libparistraceroute/libparistraceroute).

## Лицензия

MIT, см. [LICENSE](LICENSE). Код написан с нуля и не содержит кода оригинальной реализации.
