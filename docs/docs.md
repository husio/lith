# JSON API


```shell
export lith_api='http://localhost:8000/api/'
export token='122813edb8dea90702d2bffb90cf3e8b'
```

## Authentication

Authentication is done by providing a valid Authentication Session identifier.
An Authentication Session identifier is a 16 bytes value encoded as 32 characters string, for example `122813edb8dea90702d2bffb90cf3e8b`.

Authentication Session identifier must be presented either by using HTTP `Authorization` header or a HTTP cookie.

When `Authorization` header is used, `Bearer` auth schema is expected, for example `Authorization: Bearer 122813edb8dea90702d2bffb90cf3e8b`. In examples below, identifier is replaced with `$token`.

When cookie is used, `s` key should be set to the identifier value, for example `Cookie: s=122813edb8dea90702d2bffb90cf3e8b`.


## Error response

There are two formats an error message can follow, depending on the cause.

### Validation error

If error response is caused by incomplete or invalid input data, a [Validation error](#validation-error) schema is used to format the response payload.

```json
{
  "field-name": "Human readable error description.",
  "another-field-name": "Human readable error description."
}
```


### General error

If error response is caused by any other, non validation related issue, [General error](#general-error) schema is used to format the response payload.

```json
{
  "error": "Human readable error description."
}
```


## Authentication Session management

### Create a new Authentication Session

To create a new Authentication Session, send you authentication credentials.
If Two-Factor authentication is enabled, you must additionally send generated TOTP `code`.

```shell
curl "$lith_api/sessions" \
  -X POST \
  -d '{"email": "admin@example.com", "password": "admin", "code": "123456"}'
```

Code | Description
-----|------------
 201 | An Authentication Session was successfully created.
 400 | Incomplete, invalid or malformed JSON payload.
 403 | Account cannot login due to missing permissions.

```json
{
  "account_id": "1ad4ce82183f3c5027a96883bac1d7e2",
  "session_id": "122813edb8dea90702d2bffb90cf3e8b",
  "permissions": [
    "lith-admin",
    "login"
  ]
}
```



### Introspect an Authentication Session

An existing Authentication Session can be introspected.

```shell
curl "$lith_api/sessions" \
  -X GET \
  -H "Authorization: Bearer $token"
```

Code | Description
-----|------------
 200 | Authentication Session is valid and was successfully introspected.
 401 | A valid Authentication Session was not provided.

```json
{
  "account_id": "1ad4ce82183f3c5027a96883bac1d7e2",
  "session_id": "122813edb8dea90702d2bffb90cf3e8b",
  "permissions": [
    "lith-admin",
    "login"
  ]
}
```

### Delete an Authentication Session

An existing Authentication Session can be terminated.

```shell
curl "$lith_api/sessions" \
  -X DELETE \
  -H "Authorization: Bearer $token"
```

Code | Description
-----|------------
 204 | Authentication Session is valid and was successfully deleted.
 401 | A valid Authentication Session was not provided.


## Two Factor authentication

Currently, Lith supports only [Time-based One-Time Passwords](https://en.wikipedia.org/wiki/Time-based_One-Time_Password) as the second factor.

It is recommended to use an application on your phone to manage and generate TOTP tokens.

### Check if Two Factor authentication is enabled

User can check if two-factor authentication is enabled for the account.

```shell
curl "$lith_api/twofactor" \
  -X GET \
  -H "Authorization: Bearer $token"
```

Code | Description
-----|------------
 200 | A successful response contains information if the two-factor authentication is enabled for this account.
 401 | A valid Authentication Session was not provided.


```json
{
  "enabled": false
}
```

### Enable Two Factor authentication

Any account can enable two-factor authentication.
Once enabled, two-factor authentication secret cannot be changed or deleted.

Provided `secret` must be a [base32](https://en.wikipedia.org/wiki/Base32) encoded data.

Provided `code` must be the current TOTP code generated using `secret`.

```shell
curl "$lith_api/twofactor" \
  -X POST \
  -H "Authorization: Bearer $token" \
  -d '{"secret": "base32-encoded-data", "code": "123456"}'
```

In order to enable two-factor authentication, you must authenticate.
If two-factor authentication is required, you can no longer create a new authentication session.
If this is the case, only for this endpoint, you can directly send your `email` and `password` as an alternative authentication method.

```shell
curl "$lith_api/twofactor" \
  -X POST \
  -d '{"secret": "base32-encoded-data", "code": "123456", "email": "user@example.com", "password": "t0pSecret"}'
```



Code | Description
-----|------------
 201 | Two-factor authentication was successfully enabled for this account. No payload is returned.
 400 | An incomplete or malformed input. See [error response](#error-response) section for details.
 401 | A valid authentication credentials were not provided.
 409 | Two-factor authentication is already enabled for this account.


## Account management


### Create a new account

Account creation is a two step operation and require email address confirmation.

First, you must submit your email address that you would like to use to register a new account.
After this, you will receive an email message with a link to finish registration process.

```shell
curl "$lith_api/accounts" \
  -X POST \
  -d '{"email": "user@example.com"}'
```

Code | Description
-----|------------
 202 | Registration was initialized, email message with a one-time registration token was sent. No response payload.
 400 | Incomplete, invalid or malformed JSON payload.
 409 | Provided email is already used by another account.


Received email message will contain a URL with one-time registration token.
Your application is responsible for handling that URL and extracting registration token.

```shell
curl "$lith_api/accounts" \
  -X PUT \
  -d '{"password": "t0pSecret", "token": "fdf1033a39a0ffae50784b44909a97bd"}'
```

Code | Description
-----|------------
 201 | Successful registration. New account email/password combination can be used to login.
 400 | Incomplete, invalid or malformed JSON payload.
 401 | Provided one-time token is invalid or expired.
 409 | Provided email is already used by another account.

```json
{
  "account_id": "8138177c4fa45ce839d158374d1601c9"
}
```

### Reset an account password

Account password reset is a two step operation.

```shell
curl "$lith_api/passwordreset" \
  -X POST \
  -d '{"email": "user@example.com"}'
```

Code | Description
-----|------------
 202 | Password reset was initialized, email message with a one-time token was sent. No response payload.
 400 | Incomplete, invalid or malformed JSON payload.


```shell
curl "$lith_api/passwordreset" \
  -X PUT \
  -d '{"password": "t0pSecret", "token": "fdf1033a39a0ffae50784b44909a97bd"}'
```

Code | Description
-----|------------
 200 | A new account password is set.
 401 | Provided one-time token is invalid or expired.
 409 | Account email address has changed since the one-time token was generated. You must request a new password reset token.

```json
{
  "account_id": "8138177c4fa45ce839d158374d1601c9"
}
```
