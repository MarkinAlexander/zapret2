# Отложенные планы (parked)

Не реализовано сознательно. Вернуться сюда, если ACK-only воркараунд
покажет недостаточную эффективность или всплывут ошибки клон-блобов затора.

## 1. zator config.default: graceful degradation клон-стратегий

Статус: отложено пользователем. Из всего плана приемлем только `:optional`;
`fallback=fake_default_tls` отклонён — теряет суть «фейков из реальных данных».

Контекст: клон-стратегии 31–36, 39, 42 (`tls_client_hello_clone:blob=clone_vk/...`
→ `fake:blob=clone_*` → `multisplit`) падают с
`LUA ERROR: zapret-lib.lua:553: blob 'clone_vk' unavailable` +
`desync ERROR. passing packet unmodified.`, если клонирование не удалось
(фрагментированный ClientHello без reasm-данных: внеочередные фрагменты,
отменённый/выключенный реасм, малое окно сервера).

Запасной фикс (одна строка на стратегию, config.default строки 139–144, 147, 150):
добавить `:optional` потребителям блоба — `fake:blob=clone_vk:optional:...`,
`fakemultidisorder:fake_blob=clone_vk_fmd:optional:...` (39),
`fakemultisplit:fake_blob=clone_hcaptcha_fms:optional:...` (42).
Тогда при неудачном клоне фейк пропускается с DLOG, а multisplit в хвосте
цепочки выполняется; LUA ERROR исчезает. Поддержка `optional` уже есть:
zapret-antidpi.lua:457–459 (fake), orchestra/locked.lua:400–407
(fakemultidisorder) и :556–563 (fakemultisplit).

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
