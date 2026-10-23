# LABO TIME-04 — два процесса, Noise IK и подписанные утверждения времени

Источник: [WOW-CUSTODIAN-08](https://app.notion.com/p/40232a84beec8160aab4e1041cdb103a), [TIME-03](https://github.com/calex794/labo/pull/27), [TIME-01/02](https://github.com/calex794/labo/pull/28).

Исполняются **отдельные ОС-процессы** server/client в одном GitHub runner по TCP loopback 127.0.0.1. Для соединения используется настоящий Rust snow Noise_IK_25519_ChaChaPoly_BLAKE2s с заранее закреплённым статическим серверным ключом X25519. По зашифрованному каналу запрашивается 16-байтовый nonce и версия/контрольная точка, сервер Ed25519-подписью удостоверяет ответ о предполагаемом UTC. Проверки повреждения, неизвестного ключа, старого nonce, epoch, rollback, пустого ответа и подписанной лжи.

**Границы:** лабораторные постоянные ключи предсказуемые, nonce фиксирован тестом, это не безопасный production вариант. Нет реального QUIC/Roha, Roughtime, NTS, RTC, независимых серверов, W3/W4, испытаний физической задержки. Ни Noise IK, ни Ed25519 не гарантируют, что подписанное время истинно. Клиент **не меняет системное время и не возобновляет истекающие права** только на основании одной подписи. Для настоящего продукта нужен CSPRNG nonce, persistence anti-replay, динамическая ротация/отзыв ключей и независимый доказуемый bound времени.

Воспроизводимость: `cargo test`, `cargo build --release`, `python3 harness.py target/release/labo-time04-authenticated-recovery results` из `experiments/time04-noise-recovery`. CI — `.github/workflows/time04-noise-recovery.yml`.
