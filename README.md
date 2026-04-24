<div align="center">
<img width="862" height="248" alt="login_no" src="https://github.com/user-attachments/assets/c8141bae-aef7-40ff-a08e-57f769b96d66" />
</div>

# TLSS

Hello, TLSS is a small project aimed at the simplest possible work with certificates, the main goal of which is to simplify the deployment and control of certificates in the internal infrastructure, and ensure simple data portability.

## Main features:

1) Everything is stored in small and fast SQLite 💾
2) All keys in the database are encrypted 🔑
3) Your certificates are always at hand, wherever you are, just take the database file with you and you're good to go 🚀
4) Create or add your ssh keys for connecting to servers
5) Add your external CA certificates for signing server certificates and client certificates ****
6) Controlled via WEB UI

## Supported

1) Creation/revocation/automatic recreation of server certificates (regular and wildcard)
2) Creation/revocation/automatic recreation of client certificates (regular and wildcard)
3) Adding unique OID for more precise filtering
4) Automatic certificate copying mechanism to server
5) Creation of objects not linked to servers
6) Control of recreation, validity
7) CRL generation
8) Reissuance of CA with recreation of all dependent objects (for core CA only)

## How it works

### Application Launch

1) On the first application start, the console will ask 3 questions:
- login;
- password;
- salt.

2) After that, he first launch will create all necessary directories, generate a configuration file `config.yaml` and an SSH key will be generated for connecting to servers. 

3) The initial launch uses the default configuration and starts on an unsecured port, you need to make appropriate adjustments to your taste.

4) On the first login, you will land on the root/intermediate certificate generation page, without this step certificate creation will be impossible.

## Features

The login window greets you with two options, Login or Overview.



Without authorization, capabilities are limited to two sections:
1) Home with Overview subsection - serves as statistics and general information
<div align="center">
<img width="85%" alt="Pasted image 20251209172533" src="https://github.com/user-attachments/assets/855d799b-4b11-47d9-b33b-d1de100652ec" />
</div>

  2) Tools with Certificate Info subsection - allowing you to view certificate information, supporting selection through explorer or drop down.
<div align="center">
<img width="85%" alt="Pasted image 20251209163440" src="https://github.com/user-attachments/assets/f8143cc4-f34e-4aa1-bb86-236bd77a94be" />
</div>
Certificate generation is divided into two sections performing the same-name tasks:

1) Servers certs
2) Clients certs

The main differences between sections lie in additional capabilities and some certificate settings:

Servers certs section:

- Add ssh key subsection adds the ability to create your own ssh keys and use them to connect servers where generated certificates can be stored.
- Certificates are generated with TLS Web Server Authentication type
- Domain is automatically added to SAN section, even if it remains unfilled
- Creating server certificates makes it possible to save them on remote servers. For this, a server is added in the Add servers subsection, after which, when creating, you can set the "Save to server" switch.
<div align="center">
<img width="90%"  alt="image" src="https://github.com/user-attachments/assets/78e5f833-3e9b-4d1c-a5c9-e279710a9a72" />
</div>

Clients certs section:

- Add OIDs subsection adds the ability to create an additional custom field in the certificate
- Certificates are generated with TLS Web Client Authentication type

In both cases, setting the switch to "Recreate" will automatically recreate the certificate both locally and on the updated server if it was created with the Save on server switch.

### CA Revocation

Revoking a root or intermediate certificate triggers a chain reaction that leads to revocation of all certificates signed by this CA, and certificates that were already revoked will be deleted. Certificate save on server will be recreated.

### Creation/Revocation of Server or Client Certificates

Certificate revocation options differ by type:

Servers certs:
- When revoking a server certificate and subsequent rollback, the certificate does not overwrite the existing one if it was generated, that is, each certificate is unique and exists autonomously. Creation behavior is similar.

Clients certs:
- If you revoke a client certificate, then issuing a new one will overwrite the existing one, regardless of whether it was revoked or remained active.
- Client certificate creation is accompanied by the ability to set a password for subsequent container download and secure transfer.

## Possible bugs 🎃

I cannot check everything, there may be more than one bug found, I apologize 🥺

## MIT License 🎉
https://github.com/user-attachments/assets/e5511d51-0105-4ce2-bbad-525856fa2239

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



