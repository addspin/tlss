<div align="center">
<img width="862" height="248" alt="login_no" src="https://github.com/user-attachments/assets/c8141bae-aef7-40ff-a08e-57f769b96d66" />
</div>

## TLSS

Hello, TLSS is a small project aimed at the simplest possible work with certificates, the main goal of which is to simplify the deployment and control of certificates in the internal infrastructure, and ensure simple data portability.

https://github.com/user-attachments/assets/320e3ce7-9618-4c16-a88d-30ebb8369ae7

Here's the English translation of your text:

**IMPORTANT:**

**When upgrading from version 1.3.0 to 1.4.0, add/recreate (keys will already be there) the following parameters:**

Add:
```yaml
estCSRAttrs:
  rfc9908: true # true - use RFC 9908, false - use RFC 7030
```

Make changes to the existing parameter:
```yaml
CAcrl:
  subCACrlURL: https://tlss.lv.local:43000/api/v1/crl/subca/pem # CRL signed by Sub CA, for end-entity certs
  rootCACrlURL: https://tlss.lv.local:43000/api/v1/crl/rootca/pem # CRL signed by Root CA, for Sub CA certs
  unit: hours # minutes, seconds, hours
  updateInterval: 24 # interval of CRL update
```

## Last update - 19.05.26:
Details below:

**Add:** Added support for the EST protocol (RFC 7030)
According to RFC 7030, the following URIs are supported:

Mandatory:
- Distribution of CA - /.well-known/est/cacerts/
- Enrollment of Clients - /.well-known/est/simpleenroll
- Re-enrollment of Clients - /.well-known/est/simplereenroll
Optional:
- CSR Attributes - /.well-known/est/csrattrs (due to differences in the structure of the original RFC 7030 and the addition in RFC 9908, the `estCSRAttrs` parameter has been added to the configuration)
Required for proper application operation:
```yaml
estCSRAttrs:
  rfc9908: true # true - use RFC 9908, false - use RFC 7030
```

**Update:** Added configuration specifying endpoints for root CA / sub CA to retrieve CRLs (according to RFC 5280, each certificate specifies a CDP (**CRL Distribution Point**) pointing to the CRL of its issuer). The bundle is also saved.

**IMPORTANT:**

Because I forgot to add CDP links for root CA / sub CA to the configuration and instead left a link to the bundle, your current signing certificate will lack them. As a result, all issued certificates will produce an error during full verification, for example via openssl **`openssl verify -crl_check_all`**. Unfortunately, the only solution is to reissue the sub CA after changing the configuration.
The current valid configuration contains the following parameters for CDP:
```yaml
CAcrl:
  subCACrlURL: https://tlss.lv.local:43000/api/v1/crl/subca/pem # CRL signed by Sub CA, for end-entity certs
  rootCACrlURL: https://tlss.lv.local:43000/api/v1/crl/rootca/pem # CRL signed by Root CA, for Sub CA certs
  unit: hours # minutes, seconds, hours
  updateInterval: 24 # interval of CRL update
```

**Fix:** When creating a new Sub CA, the cache was not cleared, leading to the recreation of certificates signed by a revoked Sub CA

**Fix:** CRL was not updated after recreating a Sub CA (required waiting for the next update)

**Fix:** Time update (next update) in CRL

**Fix:** Fixed certificate serial number display in Certificate Info, now consistent with the database and openssl display

**Update:** Certificate revoke/rollback now updates the CRL immediately without waiting for the global update

**Add:** Added information to Certificate Info for chain debugging:
- **Subject Key Identifier** - for CA certificates, this is the identifier of their own key
- **Authority Key Identifier** - for end-entity certificates and Sub CA, points to the issuer's key (parent's `SKI`)

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
8) Reissuance of CA with recreation of all dependent objects (for core CA only)
9) API for automation
10) EST protocol support according to RFC 7030

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
2) Tools with Certificate Info subsection - allowing you to view certificate information, supporting selection through explorer or drop down.

Certificate generation is divided into two sections performing the same-name tasks:

1) Servers certs
2) Clients certs

The main differences between sections lie in additional capabilities and some certificate settings:

## Servers certs section:

- Add ssh key subsection adds the ability to create your own ssh keys and use them to connect servers where generated certificates can be stored.
- Certificates are generated with TLS Web Server Authentication type
- Domain is automatically added to SAN section, even if it remains unfilled
- Creating server certificates makes it possible to save them on remote servers. For this, a server is added in the Add servers subsection, after which, when creating, you can set the "Save to server" switch.


## Clients certs section:

- Add OIDs subsection adds the ability to create an additional custom field in the certificate
- Certificates are generated with TLS Web Client Authentication type

In both cases, setting the switch to "Recreate" will automatically recreate the certificate both locally and on the updated server if it was created with the Save on server switch.

## CA Revocation

Revoking a root or intermediate certificate triggers a chain reaction that leads to revocation of all certificates signed by this CA, and certificates that were already revoked will be deleted. Certificate save on server will be recreated.

## Creation/Revocation of Server or Client Certificates

Certificate revocation options differ by type:

Servers certs:
- When revoking a server certificate and subsequent rollback, the certificate does not overwrite the existing one if it was generated, that is, each certificate is unique and exists autonomously. Creation behavior is similar.

Clients certs:
- Similar to server certificates.

## Possible bugs 🎃
I cannot check everything, there may be more than one bug found, I apologize 🥺

## MIT License 🎉

<br></br>

# TLSS

Привет, TLSS это небольшой проект, направленный на максимально простую работу с сертфиикатами, основная цель которого упростить развертывание и контроль сертификатов во внутренней инфраструктуре, и обеспечить простую переносимость данных.

**ВАЖНО:**

**При переходе с версии 1.3.0 на 1.4.0 добавьте в конфигурацию\пересоздайте (ключи уже будут там) следующие параметры:**

Добавьте:
```yaml
estCSRAttrs:
  rfc9908: true # true - использовать RFC 9908, false - использовать RFC 7030 / use RFC 9908, false - use RFC 7030
```

Внесите изменения в уже существующий пункт: 
```yaml
CAcrl:
  subCACrlURL: https://tlss.lv.local:43000/api/v1/crl/subca/pem # CRL подписанный Sub CA, для конечных сертификатов / CRL signed by Sub CA, for end-entity certs
  rootCACrlURL: https://tlss.lv.local:43000/api/v1/crl/rootca/pem # CRL подписанный Root CA, для Sub CA сертификатов / CRL signed by Root CA, for Sub CA certs
  unit: hours # minutes, seconds, hours
  updateInterval: 24 # interval of CRL update / интервал обновления CRL
```

## Last update - 19.05.26:
Подробности ниже: 

**Add:** Добавлена поддержка протокола EST (RFC 7030)
Согласно RFC 7030 поддерживаются следующие URIs:

Обязательные:
- Distribution of CA -/.well-known/est/cacerts/
- Enrollment of Clients - /.well-known/est/simpleenroll
- Re-enrollment of Clients - /.well-known/est/simplereenroll
Опциональные:
 - CSR Attributes - /.well-known/est/csrattrs (из-за разницы в струкутере оригинальной RFC 7030 и дополнения в RFC 9908, в конфигурации добавлен пункт estCSRAttrs ) 
 Требуется внести для нормальной работы приложения 
 ```yaml
estCSRAttrs:
  rfc9908: true # true - использовать RFC 9908, false - использовать RFC 7030 / use RFC 9908, false - use RFC 7030
 ```


**Update:** Добавлена конфигурация указывающая на эндпоинты для root ca \ sub ca для получения crl (согласно RFC 5280 каждый сертификат указывает CDP (**CRL Distribution Point**) на CRL своего издателя). Бандл так же сохраняется. 

**ВАЖНО:**

Из-за того что я забыл добавить в конфигурацию ссылки на CDP для root ca\sub ca, а вместо них оставил ссылку на бандл, ваш текущий подписывающий сертификат будет без него, как следствие все выпущенные сертификаты при полной проверке например через openssl **`openssl verify -crl_check_all`** выдадут ошибку. К сожалению единственный  путь, это перевыпустить sub ca после изменения в конфигурации.
Текущий валидный конфиг содержит следующие параметры для CDP:
```yaml
CAcrl:
  subCACrlURL: https://tlss.lv.local:43000/api/v1/crl/subca/pem # CRL подписанный Sub CA, для конечных сертификатов / CRL signed by Sub CA, for end-entity certs
  rootCACrlURL: https://tlss.lv.local:43000/api/v1/crl/rootca/pem # CRL подписанный Root CA, для Sub CA сертификатов / CRL signed by Root CA, for Sub CA certs
  unit: hours # minutes, seconds, hours
  updateInterval: 24 # interval of CRL update / интервал обновления CRL
```

**Fix:** При создании нового Sub ca кеш не сбрасывался, что приводило к пересозданию сертификатов с подписью отозванного Sub ca

**Fix:** Не обновлялся CRL после пересоздания Sub ca (требовалось ждать, следующего обновления)

**Fix:** Обновления времени (следующего обновления) в crl 

**Fix:** Фикс отображения серийного номера сертификата  в Certificate Info, согласован с БД и отображением в openssl

**Update:** revoke\rollback сертификатов сразу обновляет CRL не дожидаясь глобального обновления.

**Add:** Добавлена информация  в Certificate Info для отладки цепочек:
- **Subject Key Identifier** - для CA сертификатов это идентификатор их собственного ключа
- **Authority Key Identifier** - у конечных сертификатов и Sub CA указывает на ключ издателя (`SKI` родителя)

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
8) Превыпуск CA с пересозданием всех заисимых объектов 
9) API для автоматизации
10) Поддержка протокола EST RFC 7030

## Начало использования

1) Первый запуск создает все каталоги и генерирует конфиграционный файл `config.yaml`, вероятно вам захочется отредактировать следующие поля:
   - hostname
   - protocol
   - authConfig
2) После первой авторизации в UI, вы попадете на страницу генерации CA\SubCA, сгененируйте их или дальнейшее создание сертификатов будет невозможно 

## Возможные баги 🎃
Я не в силах проверить все сразу, возможно найдется не один баг, прошу прощения 🥺

## Лицензия MIT 🎉



