# FORK.md — ранбук обслуживания форка

Инструкция для меня самого: как проверять PR у автора, подтягивать его новые
версии и собирать свой релиз `v<версия>-reasm-fix`. Прочитай этот файл перед
каждым обновлением.

## Устройство форка

| Ремоут | Репозиторий |
|---|---|
| `origin` | `MarkinAlexander/zapret2` (мой форк) |
| `upstream` | `bol-van/zapret2` (автор) |

### Ветки

| Ветка | Что это |
|---|---|
| `master` | **Зеркало `upstream/master`** + единственный форк-файл `.github/workflows/build-fork.yml` (+ этот FORK.md). НЕ содержит reasm-фикс. Обновляется reset-ом (см. ниже). |
| `build/v<ver>-reasm-fix` | Релизная ветка: тег автора `v<ver>` + 2 коммита reasm-фикса + 1 коммит с workflow. С неё запускается CI-релиз. |
| `feature-reasm-autodetect` | PR-ветка автора (#303): тег `v<ver>` + только 2 коммита reasm-фикса (без workflow — автору он не нужен). |
| `build/v1.0.5.1-reasm-fix` | Эталонная релизная ветка прошлой версии, источники фикса `47a0aa3` + `6348d39`. |
| `backup-before-clean-pr`, тег `backup/master-pre-1052` | Бэкапы старого master до перезатирания (до 2026-09-16). Можно удалить, когда точно не нужны. |

### Reasm-фикс — где исходники

Два коммита, трогают `nfq2/{desync.c, packet_queue.c/h, pools.c/h}`:

1. `fix TLS reasm desync on hardware fastpath routers` — при неполном
   реассемблинге и ретрансмиссии отбрасывает reasm и подменяет первый фрагмент
   пустым TCP ACK (пакет не уходит в fastpath, ClientHello не утекает).
2. `autodetect hw fastpath for TLS reasm` — срабатывание по автодетекту:
   счётчик ретрансмиссий на IP сервера в ipcache, порог 2.

**Правило переноса:** не искать старые хеши, а забирать два верхних reasm-коммита
последней build-ветки (`~2` и `~1` под workflow-коммитом) — там уже лежат
разрешённые конфликты:

```bash
git cherry-pick build/v<ver>-reasm-fix~2 build/v<ver>-reasm-fix~1
```

## Чеклист: «У автора вышла новая версия»

Ниже `V` = новая версия автора, например `1.0.5.2`; тег `v$V`.

### 0. Пре-чек

```bash
git status            # ветка master, каталог чист (untracked binaries/, .idea/ и пр. не трогаем)
git fetch upstream --tags --prune
git rev-parse v$V                 # тег существует? запомнить хеш
git log --oneline upstream/master -15   # что нового после тега (обычно docs)
git log --oneline v$V..upstream/master   # коммиты ПОСЛЕ тега — в релиз не идут
```

Заодно глянуть, не задел ли автор `nfq2/desync.c`, `packet_queue.*`, `pools.*`
(конфликтные файлы фикса):

```bash
git diff --stat v<старый тег>..v$V -- nfq2/
```

### 1. Проверить статус своего PR у автора

PR: <https://github.com/bol-van/zapret2/pull/303>

- Веб: открыть PR, смотреть state, комменты, «This branch has no conflicts».
- Без gh: `WebFetch https://api.github.com/repos/bol-van/zapret2/pulls/303`
  — поля `state`, `merged`, `mergeable_state`, `head.sha`.
- Если PR смержили — фикс уже у автора, своя релизная ветка больше не нужна
  (можно просто собирать официальный релиз). Следующие шаги пропускаем.

### 2. Обновить master (reset, не merge)

Master — зеркало, история форка не важна (бэкапы уже в тегах/ветках).

```bash
git tag backup/master-pre-$V master          # страховка (один раз)
git push origin backup/master-pre-$V
git switch master
git reset --hard upstream/master
git restore --source backup/master-pre-$V -- .github/workflows/build-fork.yml
# дефолт input version в файле поправить на v$V-reasm-fix (строка default:)
git add .github/workflows/build-fork.yml
git commit -m "build-fork: workflow на чистом upstream v$V"
git push --force-with-lease origin master
```

### 3. Создать релизную ветку build/v$V-reasm-fix

```bash
git switch -c build/v$V-reasm-fix v$V     # база — тег автора, НЕ upstream/master
git cherry-pick build/v<предыдущая версия>-reasm-fix~2 \
                  build/v<предыдущая версия>-reasm-fix~1   # либо 47a0aa3 6348d39
git restore --source master -- .github/workflows/build-fork.yml
git add .github/workflows/build-fork.yml
git commit -m "build-fork: workflow для релиза v$V-reasm-fix"
git diff --stat v$V      # ожидаемо: nfq2/{desync.c,packet_queue.*,pools.*} + workflow. НИЧЕГО БОЛЬШЕ
git push -u origin build/v$V-reasm-fix
```

Если cherry-pick конфликтует в `desync.c` (автор любит его рефакторить):
нужны ОБЕ стороны — рефакторинг автора (dp_match и пр.) + наш reasm/ACK-код.
После ручного разрешения `git cherry-pick --continue`, и именно эта разрешённая
версия поедет в следующий раз через правило `~2 ~1`.

### 4. Тестовая сборка без релиза

Веб: *Actions → build-fork → Run workflow* → ветка `build/v$V-reasm-fix`,
`version` = `v$V-reasm-fix`, `make_release` = **false** → Run.

Дождаться: build-linux (11 архов), build-android (4), build-freebsd — все зелёные.

### 5. Релиз

Тот же запуск, но `make_release` = **true**. Джоба `release` сама:

- упакует бандлы как у автора (`zapret2-v$V-reasm-fix.tar.gz/.zip/-openwrt-embedded.tar.gz`,
  `sha256sum.txt`) + `binaries-v$V-reasm-fix.tar.gz` для keenetic-репо;
- создаст тег `v$V-reasm-fix` и релиз с русским описанием фикса.

Проверка релиза: *Releases → v$V-reasm-fix*, 5 ассетов (`tar.gz`, `.zip`,
`-openwrt-embedded.tar.gz`, `binaries-*.tar.gz`, `sha256sum.txt`), sha256 на месте.
Тег должен стоять на вершине build-ветки: `git fetch origin --tags && git log --oneline -1 v$V-reasm-fix`.

### 6. Обновить PR-ветку (пока PR не смержили)

```bash
git switch -C feature-reasm-autodetect v$V
git cherry-pick build/v$V-reasm-fix~2 build/v$V-reasm-fix~1
git push --force-with-lease origin feature-reasm-autodetect
```

После пуша открыть PR и убедиться: mergeable = clean, 2 коммита, diff только
по nfq2/. При желании оставить коммент автору («ребейзнул на v$V»).

## Типичные грабли

- **Версия в workflow только из input** — `inputs.version` без fallback на имя
  тега. Всегда заполнять поле `version` при запуске, иначе пустая строка.
- **Тег автора ≠ вершина upstream/master** — после тега часто идут docs-коммиты.
  Build-ветка строится ОТ ТЕГА (релиз соответствует официальному), master —
  от вершины (зеркало).
- **`binaries/linux-*`, `*.rar`, `dubug*.log` — untracked-мусор**, не коммитить.
- **UPX затирает строки** — версию проверять в CI до упаковки (шаг уже есть).
- **Тег релиза** — шаг «Ensure release tag» в workflow сам пушит тег на
  GITHUB_SHA build-ветки. До фикса 2026-09-16 softprops создавал отсутствующий
  тег на default branch (master, без фикса) — если тег где-то создан неверно,
  удалить релиз+тег и перезапустить workflow.
- **Force-push — только `--force-with-lease`**, и никогда — в PR-ветку автора.
- **Не мержить upstream в master** — только reset; иначе вернётся устаревшая
  итерация фикса и конфликты в desync.c (уже проходили, вычищено 2026-09-16).

## История обновлений форка

| Дата | Что сделали |
|---|---|
| 2026-09-17 | Диагноз медленного старта/установки на слабых CPU: 92% времени = загрузка TCP_RKN_list.txt (125K хостов, ~790 мс на MT7621) при каждом запуске + ~200 мс UPX. Ветка `perf/skip-lists-in-dry-run`: --dry-run не грузит содержимое hostlists/ipsets (910→40 мс на боевом конфиге). Кандидат в PR автору. |
| 2026-09-16 | Подтянут v1.0.5.2: master сброшен на зеркало upstream, собрана ветка `build/v1.0.5.2-reasm-fix` (cherry-pick без конфликтов), PR #303 ребейзнут (mergeable clean), релиз `v1.0.5.2-reasm-fix` (пересоздан после фикса тега в workflow: f05aa94). |
| 2026-09-08 | Релиз `v1.0.5.1-reasm-fix` с чистыми коммитами `47a0aa3`+`6348d39`. |
| 2026-09-01 | Открыт PR #303. |
