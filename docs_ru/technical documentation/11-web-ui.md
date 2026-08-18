# 11. Веб-интерфейс

Классический server-side rendering на Go-шаблонах плюс HTMX для частичных обновлений.
Никакого SPA-фреймворка и сборки - вся статика встроена в бинарник через `go:embed`.

## Встраивание ресурсов

```go
//go:embed template
var templateFS embed.FS

//go:embed static
var staticFS embed.FS
```

Приложение собирается в один самодостаточный файл: шаблоны и статика внутри.
Обратная сторона - изменения в `template/` и `static/` требуют пересборки, править
их «на живом сервере» нельзя.

Движок - `github.com/gofiber/template/html/v2` поверх `html/template` стандартной
библиотеки.

## Структура шаблонов

```
template/
├── main/           header, body, footer - общий каркас
├── navigation/     меню: авторизованное и публичное
├── login/          форма входа
├── overview/       сводка на главной
├── add_server/     серверы
├── add_ssh/        SSH-ключи
├── add_certs/      выпуск серверных сертификатов
├── revoke_certs/   отзыв серверных
├── add_entity/     сущности для клиентских
├── add_oid/        пользовательские OID
├── add_user_certs/ выпуск клиентских
├── user_revoke_certs/  отзыв клиентских
├── est/            EST: пользователи и выпуск
├── est_revoke_certs/   EST: отзыв
├── ca/             Root, Sub и внешние CA
├── ca_revoke_certs/    отзыв CA
├── api_keys/       API-ключи
└── cert_info/      разбор загруженного сертификата
```

Внутри раздела действует единое соглашение:

| Файл | Роль |
|---|---|
| `<name>.html` | Полная страница: подключает header, меню, content, footer |
| `<name>-content.html` | Содержимое для HTMX-подстановки без перезагрузки |
| `<name>List-tpl.html` | Таблица со списком, обновляется отдельно |
| `<name>List.html` | Обёртка вокруг `-tpl` для рендера из контроллера |

## Двойной рендер

Каждый контроллер страницы различает обычный переход и HTMX-запрос:

```go
if c.Get("HX-Request") != "" {
    return c.Render("addESTCerts-content", data, "")   // только контент
}
return c.Render("est/addESTCerts", data)               // страница целиком
```

Благодаря этому переход по меню не перезагружает страницу, а прямое открытие URL
или обновление по F5 работает штатно.

## HTMX

Библиотека - `static/js/htmx.min.js`. Основные приёмы:

```html
<!-- Переход по меню -->
<a hx-get="/add_est_certs" hx-target="#main-content" hx-swap="innerHTML" hx-push-url="true">

<!-- Отправка формы как JSON -->
<form hx-post="/add_est_certs" hx-ext="json-enc-custom" parse-types="true" hx-swap="none">

<!-- Удаление строки таблицы -->
<button hx-post="/remove_est_cert" hx-target=".est_cert_id_5" hx-trigger="remove">
```

Расширение `json-enc-custom` (`static/js/ext/`) кодирует форму в JSON вместо
`application/x-www-form-urlencoded`, а `parse-types="true"` приводит числовые поля к
числам - иначе `c.Bind().JSON()` на стороне Go не разберёт `"TTL": "365"` в `int`.

### Соглашение по обновлению списков

Обработчики удаления и отзыва возвращают **пустой** партиал списка:

```go
return c.Render("est/estUserList-tpl", fiber.Map{})
```

Так сделано во всех разделах. Причина: `hx-target` указывает на конкретную строку
(`.est_user_id_5`), и htmx подменяет именно её. Если вернуть таблицу целиком с
данными, она окажется вложенной внутрь `<tr>` и разметка сломается.

## Прочие скрипты

| Файл | Назначение |
|---|---|
| `sweetalert2.all.min.js` | Диалоги подтверждения - удаление и отзыв требуют ввода имени объекта |
| `table-sort.js` | Сортировка таблиц по клику на заголовок |
| `search-object.js` | Фильтрация списков и таблиц по подстроке |
| `keylength.js` | Переключение допустимых длин ключа при смене алгоритма |
| `drag-drop.js`, `ssh-upload.js`, `ext-ca-upload.js` | Загрузка файлов перетаскиванием |
| `menu-active.js` | Подсветка активного пункта меню |
| `api-key-show.js` | Одноразовый показ созданного API-ключа |
| `addtag.js` | Ввод SAN и OID тегами |
| `bootstrap.bundle.js` | Сворачиваемые блоки меню, выпадающие списки |

## Поиск

`search-object.js` работает через делегирование событий: слушатель висит на
`document` и разбирает атрибут `name` у поля ввода. Это важно для HTMX - таблицы
пересоздаются динамически, и обработчики, навешанные напрямую на элементы, терялись бы
после каждой подмены.

Соответствие имени поля и области поиска задано в `switch`:

| `name` поля | Что фильтрует |
|---|---|
| `search-server`, `search-entity`, `search-est-user` | Кнопки в левой панели |
| `search-servers`, `search-est-users` | Строки таблицы в `.servers_table` |
| `search-certs`, `search-est-certs` | Строки таблиц сертификатов |

Добавляя новый раздел с поиском, нужно **и** задать `name` в шаблоне, **и** добавить
ветку в `switch` - иначе поле будет присутствовать, но ничего не делать.

## Сессии

`middleware.InitSessionStore` настраивает хранилище:

| Параметр | Значение | Смысл |
|---|---|---|
| `CookieSameSite` | `Lax` | Совместимость с Safari |
| `CookieSecure` | `app.protocol == "https"` | Автоматически по конфигурации |
| `CookieHTTPOnly` | `true` | Недоступна из JavaScript |
| `IdleTimeout` | 30 минут | Продлевается при активности |
| `CookieSessionOnly` | `false` | Переживает закрытие браузера |

Хранилище - in-memory, поэтому **перезапуск приложения разлогинивает всех**.

## Публичные страницы

`/overview` и `/cert_info` доступны без входа и используют
`menu-left-public-tpl.html` - сокращённое меню. Контроллеры различают состояние через
`middleware.IsAuthenticated(c)` и выбирают соответствующий шаблон.

Раздел **Certificate Info** разбирает загруженный пользователем сертификат: выводит
Subject, издателя, серийный номер (в hex, как в базе), сроки, SAN, KeyUsage, CDP, AIA,
а также SKI и AKI - последние удобны при отладке цепочек и CRL.
