# TLSS - документация

Документация разделена на две части: одна отвечает на вопрос «как пользоваться»,
вторая - «как устроено».

## Пользовательская документация

[user documentation/](user%20documentation/contents.md) - запуск, настройка, работа
через веб-интерфейс.

| Документ | Содержание |
|---|---|
| [Первый запуск и инициализация](user%20documentation/01-getting-started.md) | Что спрашивает приложение при старте, создание CA, проверка работоспособности |
| [Подготовка к продовой среде](user%20documentation/02-production-setup.md) | Какие параметры изменить перед эксплуатацией и почему |
| [Работа с сертификатами](user%20documentation/03-working-with-certificates.md) | Разделы интерфейса, типы сертификатов, отзыв и пересоздание |

## Техническая документация

[technical documentation/](technical%20documentation/contents.md) - устройство
компонентов, схема базы, реализация протоколов.

| Тема | Документ |
|---|---|
| Архитектура, слушатели, порядок запуска | [01-architecture.md](technical%20documentation/01-architecture.md) |
| Разбор `config.yaml` | [02-configuration.md](technical%20documentation/02-configuration.md) |
| Таблицы и связи | [03-database.md](technical%20documentation/03-database.md) |
| Криптография, иерархия CA | [04-crypto.md](technical%20documentation/04-crypto.md) |
| Жизненный цикл сертификатов | [05-certificates.md](technical%20documentation/05-certificates.md) |
| CRL - RFC 5280 | [06-crl.md](technical%20documentation/06-crl.md) |
| OCSP - RFC 6960, RFC 5019 | [07-ocsp.md](technical%20documentation/07-ocsp.md) |
| EST - RFC 7030 | [08-est.md](technical%20documentation/08-est.md) |
| REST API и аутентификация | [09-api.md](technical%20documentation/09-api.md) |
| Фоновые чекеры и монитор | [10-checkers.md](technical%20documentation/10-checkers.md) |
| Веб-интерфейс и шаблоны | [11-web-ui.md](technical%20documentation/11-web-ui.md) |
| Тестовые скрипты | [12-testing.md](technical%20documentation/12-testing.md) |

## Быстрые ответы

| Вопрос | Где смотреть |
|---|---|
| Как запустить в первый раз | [Первый запуск](user%20documentation/01-getting-started.md) |
| Что поменять перед продом | [Продовая среда](user%20documentation/02-production-setup.md) |
| Почему не выпускаются сертификаты | Не созданы Root и Sub CA - [Первый запуск](user%20documentation/01-getting-started.md) |
| Как проверить, что отзыв работает | [Тестирование](technical%20documentation/12-testing.md) |
| Какие RFC реализованы | [Оглавление техдокументации](technical%20documentation/contents.md) |
