
<img width="862" height="248" alt="login_no" src="https://github.com/user-attachments/assets/c8141bae-aef7-40ff-a08e-57f769b96d66" />

# TLSS

Hello, TLSS is a small project aimed at the simplest possible work with certificates, the main goal of which is to simplify the deployment and control of certificates in the internal infrastructure, and ensure simple data portability.

## Main features:

1) Everything is stored in small and fast SQLite 💾
2) All keys in the database are encrypted 🔑
3) Your certificates are always at hand, wherever you are, just take the database file with you and you're good to go 🚀
4) Controlled via WEB UI

## Supported

1) Creation/revocation/automatic recreation of server certificates (regular and wildcard)
2) Creation/revocation/automatic recreation of client certificates (regular and wildcard)
3) Adding unique OID for more precise filtering
4) Automatic certificate copying mechanism to server
5) Creation of objects not linked to servers
6) Control of recreation, validity
7) CRL generation
8) Reissuance of CA with recreation of all dependent objects

## Getting started

1) The first launch will create all necessary directories and generate a configuration file `config.yaml`. You will probably want to edit the following fields:
   - hostname
   - protocol
   - authConfig
2) After your first login via the UI, you will be redirected to the page to generate CA/SubCA. Please generate them, otherwise creation of certificates will be impossible.

## Possible bugs 🎃

I cannot check everything, there may be more than one bug found, I apologize 🥺

## MIT License 🎉

<br></br>

# TLSS

Привет, TLSS это небольшой проект, направленный на максимально простую работу с сертфиикатами, основная цель которого упростить развертывание и контроль сертификатов во внутренней инфраструктуре, и обеспечить простую переносимость данных.

## Основные особенности

1) Все хранится в маленькой и быстрой sqlite 💾
2) Все ключи в базе зашифрованы 🔑
3) Ваши сертфикиаты всегда под рукой, где бы вы небыли, достаточно взять с собой файл базы и вы в деле 🚀
4) Управляется через WEB UI

## Поддерживается

1) Создание\отзыв\автоматическое пересоздание серверных сертфиикатов (обычных и wildcard)
2) Создание\отзыв\автоматическое пересоздание клиентских сертификатов (обычных и wildcard)
3) Добавление уникального OID для более тонкой фильтрации
4) Механизм автоматического копирования сертификатов на сервер
5) Создание объектов не связаных с серверами
6) Контроль пересоздания, валидности
7) Генерация CRL
8) Превыпуск CA с пересозданием всех заисимых объектов 

## Начало использования

1) Первый запуск создает все каталоги и генерирует конфиграционный файл `config.yaml`, вероятно вам захочется отредактировать следующие поля:
   - hostname
   - protocol
   - authConfig
2) После первой авторизации в UI, вы попадете на страницу генерации CA\SubCA, сгененируйте их или дальнейшее создание сертификатов будет невозможно 

## Возможные баги 🎃
Я не в силах проверить все сразу, возможно найдется не один баг, прошу прощения 🥺

## Лицензия MIT 🎉
https://github.com/user-attachments/assets/e5511d51-0105-4ce2-bbad-525856fa2239



