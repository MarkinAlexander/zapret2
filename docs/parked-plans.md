# Отложенные планы (parked)

Не реализовано сознательно. Вернуться сюда, если ACK-only воркараунд
покажет недостаточную эффективность или всплывут ошибки клон-блобов затора.

## 1. zator config.default: graceful degradation клон-стратегий

Статус: ПРИМЕНЕНО (ветка zator, коммит cec2ff7) — вариант с
`fallback=fake_default_tls`. `:optional` отклонён автором затора.

Контекст: клон-стратегии 31–36, 39, 42 (`tls_client_hello_clone:blob=clone_vk/...`
→ `fake:blob=clone_*` → `multisplit`) падали с
`LUA ERROR: zapret-lib.lua:553: blob 'clone_vk' unavailable` +
`desync ERROR. passing packet unmodified.`, если клонирование не удалось
(фрагментированный ClientHello без reasm-данных: внеочередные фрагменты,
отменённый/выключенный реасм, малое окно сервера, старый nfqws2 без
реасм-фиксов).

Применённый фикс: в config.default (строки 139–144, 147, 150) каждый шаг
`tls_client_hello_clone:blob=clone_*` получил `:fallback=fake_default_tls`
(поддержка в zapret-antidpi.lua:384–387). При неудачном клоне блоб
подменяется встроенным fake_default_tls — LUA ERROR исчезает, стратегия
(модификаторы + multisplit) продолжает работать на любой версии zapret2
с поддержкой аргумента fallback.

## 2. zapret2 lua: частичное клонирование ClientHello

Статус: отложено, ожидает решения по п.1 (пересекается по симптомам).

Суть: `tls_dissect(tls, offset, partialOK)` уже умеет частичный разбор
(усечённая запись, префикс полей, обрыв списка расширений на первом неполном),
а `tls_reconstruct*` пересчитывает все длины — из усечённого разбора получается
валидный короткий ClientHello. Но `tls_client_hello_mod` (zapret-lib.lua:1599)
вызывает `tls_dissect(tls)` строго и на фрагменте возвращает nil → клон
не создаётся.

Фикс — в zapret-lib.lua, первая строка функции:

```lua
local tdis = tls_dissect(tls)
if not tdis then
	-- fragmented client hello without reasm data (out-of-order segments,
	-- cancelled or disabled reasm). dissect the available prefix;
	-- tls_reconstruct will build a valid shorter hello with recomputed lengths
	tdis = tls_dissect(tls, 1, true)
	if tdis then DLOG("tls_client_hello_mod: dissecting partial client hello") end
end
```

Семантика «фейки из реальных данных» сохраняется: клон = префикс реального
ClientHello с заменённым SNI. Для полных данных путь не меняется (строгий
разбор идёт первым). Lua-библиотеки грузятся с диска (luaL_dofile, lua.c),
бинарь пересобирать не нужно — только заменить /opt/zapret2/lua/zapret-lib.lua.

Проверка после применения: в автопрогоне затора стратегии 31–36/39/42 не дают
`LUA ERROR ... unavailable`; в debug-логе видны `dissecting partial client hello`
и `tls_client_hello_clone: cloned to desync.clone_vk`.
