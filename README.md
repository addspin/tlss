<div align="center">
<img width="862" height="248" alt="login_no" src="https://github.com/user-attachments/assets/c8141bae-aef7-40ff-a08e-57f769b96d66" />
</div>

## TLSS

Hello, TLSS is a small project aimed at the simplest possible work with certificates, the main goal of which is to simplify the deployment and control of certificates in the internal infrastructure, and ensure simple data portability.

https://github.com/user-attachments/assets/320e3ce7-9618-4c16-a88d-30ebb8369ae7

📖 **Documentation:** [docs_en/](docs_en/) - initialization, production setup and technical reference.

⚠️ **Upgrading?** Read [CHANGELOG.md](CHANGELOG.md) first - some versions require changes in `config.yaml`.

## Main features:

1) Everything is stored in small and fast SQLite
2) All keys in the database are encrypted
3) Your certificates are always at hand, wherever you are, just take the database file with you and you're good to go
4) Create or add your ssh keys for connecting to servers
5) Add your external CA certificates for signing server certificates and client certificates
6) Controlled via WEB UI
7) API

## Supported

1) Creation/revocation/automatic recreation of server certificates (regular and wildcard)
2) Creation/revocation/automatic recreation of client certificates (regular and wildcard)
3) Adding unique OID for more precise filtering
4) Automatic certificate copying mechanism to server
5) Creation of objects not linked to servers
6) Control of recreation, validity
7) CRL generation
8) OCSP responder according to RFC 6960 and RFC 5019
9) Reissuance of CA with recreation of all dependent objects (for core CA only)
10) API for automation
11) EST protocol support according to RFC 7030

## Possible bugs 🎃
I cannot check everything, there may be more than one bug found, I apologize 🥺

## MIT License 🎉

<br></br>

# TLSS

Привет, TLSS это небольшой проект, направленный на максимально простую работу с сертфиикатами, основная цель которого упростить развертывание и контроль сертификатов во внутренней инфраструктуре, и обеспечить простую переносимость данных.

📖 **Документация:** [docs_ru/](docs_ru/) - инициализация, настройка для продовой среды и техническая справка.

⚠️ **Обновляетесь?** Сначала прочитайте [CHANGELOG.md](CHANGELOG.md) - некоторые версии требуют изменений в `config.yaml`.

## Основные особенности

1. Все хранится в sqlite.
2. Все ключи\пароли в базе зашифрованы.
3. Бэкапы и перенос данных не проблема - просто скопируй файл с базой + конфигурация.
4. Управляется через WEB UI.
5. API.

## Поддерживается

1) Создание\отзыв\автоматическое пересоздание серверных сертфиикатов (обычных и wildcard)
2) Создание\отзыв\автоматическое пересоздание клиентских сертификатов (обычных и wildcard)
3) Добавление уникального OID для более тонкой фильтрации
4) Механизм автоматического копирования сертификатов на сервер
5) Создание объектов не связаных с серверами
6) Контроль пересоздания, валидности
7) Генерация CRL
8) OCSP респондер согласно RFC 6960 и RFC 5019
9) Превыпуск CA с пересозданием всех заисимых объектов
10) API для автоматизации
11) Поддержка протокола EST RFC 7030

## Возможные баги 🎃
Я не в силах проверить все сразу, возможно найдется не один баг, прошу прощения 🥺

## Лицензия MIT 🎉
