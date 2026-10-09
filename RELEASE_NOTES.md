Первый релиз paris-traceroute-go: реализация Paris Traceroute и MDA на Go.

- Алгоритмы: `paris` (фиксированный flow-id) и `mda` (поиск всех балансируемых путей).
- Протоколы проб: UDP, ICMP, TCP (TCP только на Linux); IPv4 и IPv6.
- Вывод в текстовом виде и JSON, MPLS-метки из ICMP-расширений.
- Работа за NAT, в том числе за NAT, который не восстанавливает контрольную сумму.

Архивы: `*_linux_*.tar.gz` для Linux, `*_windows_*.zip` для Windows (amd64 и arm64), суммы SHA-256 в `checksums.txt`.
Запуск требует root/CAP_NET_RAW на Linux и прав администратора на Windows (см. README).
