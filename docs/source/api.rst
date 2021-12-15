JSON API
========

Authentication
--------------

Authentication is done by providing a valid Authentication Session identifier.
An Authentication Session identifier is a 16 bytes value encoded as 32 characters string, for example ``122813edb8dea90702d2bffb90cf3e8b``.

Authentication Session identifier must be presented either by using HTTP `Authorization` header or a HTTP cookie.

When ``Authorization`` header is used, ``Bearer`` auth schema is expected, for example ``Authorization: Bearer 122813edb8dea90702d2bffb90cf3e8b``.

When cookie is used, ``s`` key should be set to the identifier value, for example ``Cookie: s=122813edb8dea90702d2bffb90cf3e8b``.

.. _error-response:

Error response
--------------

There are two formats an error message can follow, depending on the cause.


.. _general-error:

General error
^^^^^^^^^^^^^

If error response is caused by any other, non validation related issue, general error schema is used to format the response payload.

.. code-block:: json

    {
      "error": "Human readable error description."
    }


.. _validation-error:

Validation error
^^^^^^^^^^^^^^^^

If error response is caused by incomplete or invalid input data, a validation error schema is used to format the response payload.


.. code-block:: json

    {
      "field-name": "Human readable error description.",
      "another-field-name": "Human readable error description."
    }


Authentication Session management
---------------------------------


Create a new Authentication Session
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. http:post:: /sessions

   To create a new Authentication Session, send you authentication credentials.
   If Two-Factor authentication is enabled, you must additionally send a generated `Time-based One-Time Password`_ ``code``.

   **Example request**:

   .. sourcecode:: http

      POST /sessions HTTP/1.1
      Content-Type: application/json

      {
        "email": "admin@example.com",
        "password": "admin",
        "code": "123456"
      }

   :<json string email: The email used to register the account.
   :<json string password: The account password in plain text.
   :<json string code: Required if two-factor is enabled. A generated, 6-digit :abbr:`TOTP (Time-based One-Time Passwords)` token.

   **Example response body**:

   .. sourcecode:: json

      {
        "account_id": "1ad4ce82183f3c5027a96883bac1d7e2",
        "session_id": "122813edb8dea90702d2bffb90cf3e8b",
        "permissions": [
          "lith-admin",
          "login"
        ]
      }

   :>json string account_id: The identifier of the account that this authentication session represents.
   :>json string session_id: The identifier of this authentication session.
   :>json list of strings permissions: A list of permissions that this session grants.

   :statuscode 201: An Authentication Session was successfully created.
   :statuscode 400: Incomplete, invalid or malformed JSON payload. See :ref:`error-response` section for details.
   :statuscode 403: Account cannot login due to missing permissions.


Introspect an existing Authentication Session
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. http:get:: /sessions

   An existing Authentication Session can be introspected.

   **Example request**:

   .. sourcecode:: http

      GET /sessions HTTP/1.1
      Authorization: Bearer 122813edb8dea90702d2bffb90cf3e8b

   **Example response body**:

   .. sourcecode:: json

      {
        "account_id": "1ad4ce82183f3c5027a96883bac1d7e2",
        "session_id": "122813edb8dea90702d2bffb90cf3e8b",
        "permissions": [
          "lith-admin",
          "login"
        ]
      }

   :>json string account_id: The identifier of the account that this authentication session represents.
   :>json string session_id: The identifier of this authentication session.
   :>json list of strings permissions: A list of permissions that this session grants.

   :statuscode 200: Authentication Session is valid and was successfully introspected.
   :statuscode 401: A valid Authentication Session was not provided.

Terminate an existing Authentication Session
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. http:delete:: /sessions

   An existing Authentication Session can be terminated.

   **Example request**:

   .. sourcecode:: http

      DELETE /sessions HTTP/1.1
      Authorization: Bearer 122813edb8dea90702d2bffb90cf3e8b

   :statuscode 204: Authentication Session is valid and was successfully deleted.
   :statuscode 401: A valid Authentication Session was not provided.




Two Factor authentication
-------------------------

Currently, Lith supports only `Time-based One-Time Passwords`_ as the second factor.

It is recommended to use an application on your phone to manage and generate :abbr:`TOTP (Time-based One-Time Passwords)` tokens.


Check if Two-Factor authentication is enabled
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. http:get:: /twofactor

   User can check if two-factor authentication is enabled for the account.

   **Example request**:

   .. sourcecode:: http

      GET /twofactor HTTP/1.1
      Authorization: Bearer 122813edb8dea90702d2bffb90cf3e8b


   **Example response body**:

   .. sourcecode:: json

      {
        "enabled": false
      }

   :>json boolean enabled: True if two-factor authentication is enabled and required.

   :statuscode 200: A successful response contains information if the two-factor authentication is enabled for this account.
   :statuscode 401: A valid Authentication Session was not provided.



Enable Two-Factor authentication
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. http:post:: /twofactor

   Any account can enable two-factor authentication.
   Once enabled, two-factor authentication secret cannot be changed or deleted.

   **Example request**:

   .. sourcecode:: http

      POST /twofactor HTTP/1.1
      Authorization: Bearer 122813edb8dea90702d2bffb90cf3e8b
      Content-Type: application/json

      {
        "secret": "base32-encoded-data",
        "code": "123456"
      }

   :<json string secret: A `base32`_ encoded secret value.
   :<json string code: The current :abbr:`TOTP (Time-based One-Time Passwords)` code generated using `secret`.

   In order to enable two-factor authentication, you must authenticate.
   If two-factor authentication is required, you can no longer create a new authentication session.
   If this is the case, only for this endpoint, you can directly send your `email` and `password` as an alternative authentication method.

   **Example request**:

   .. sourcecode:: http

      POST /twofactor HTTP/1.1
      Content-Type: application/json

      {
        "secret": "base32-encoded-data",
        "code": "123456",
        "email": "user@example.com",
        "password": "t0pSecret"
      }

   :<json string secret: A `base32`_ encoded secret value.
   :<json string code: The current, 6-digit :abbr:`TOTP (Time-based One-Time Passwords)` code generated using provided ``secret``.
   :<json string email: An email address used for the account registration.
   :<json string password: Account password in plain text.

   :statuscode 201: Two-factor authentication was successfully enabled for this account. No payload is returned.
   :statuscode 400: An incomplete or malformed input. See :ref:`error-response` section for details.
   :statuscode 401: A valid authentication credentials were not provided.
   :statuscode 409: Two-factor authentication is already enabled for this account.


Account management
------------------


Create a new account
^^^^^^^^^^^^^^^^^^^^

.. http:post:: /accounts

   Account creation is a two step operation and require email address confirmation.

   First, you must submit your email address that you would like to use to register a new account.
   After this, you will receive an email message with a link to finish registration process.

   **Example request**:

   .. sourcecode:: http

      POST /accounts HTTP/1.1
      Content-Type: application/json

      {
        "email": "user@example.com"
      }

   :<json string email: An email address that should be used to authenticate.

   :statuscode 202: Registration was initialized, email message with a one-time registration token was sent. No response payload.
   :statuscode 400: Incomplete, invalid or malformed JSON payload.
   :statuscode 409: Provided email is already used by another account.


.. http:put:: /accounts

   Received email message will contain a URL with one-time registration token.
   Your application is responsible for handling that URL and extracting registration token.

   **Example request**:

   .. sourcecode:: http

      PUT /accounts HTTP/1.1
      Content-Type: application/json

      {
        "password": "t0pSecret",
        "token": "fdf1033a39a0ffae50784b44909a97bd"
      }

   :<json string password: A plain text password that will be set for this account.
   :<json string token: The one-time token sent via email.

   **Example response body**:

   .. sourcecode:: json

      {
        "account_id": "8138177c4fa45ce839d158374d1601c9"
      }

   :>json string account_id: The identifier of the newly created account.

   :statuscode 201: Successful registration. New account email/password combination can be used to login.
   :statuscode 400: Incomplete, invalid or malformed JSON payload.
   :statuscode 401: Provided one-time token is invalid or expired.
   :statuscode 409: Provided email is already used by another account.



Reset an account password
^^^^^^^^^^^^^^^^^^^^^^^^^

.. http:post:: /passwordreset

   Account password reset is a two step operation.

   **Example request**:

   .. sourcecode:: http

      POST /passwordreset HTTP/1.1
      Content-Type: application/json

      {
        "email": "user@example.com"
      }

   :>json string email: The email address connected to the account we want to access.

   :statuscode 202: Password reset was initialized, email message with a one-time token was sent. No response payload.
   :statuscode 400: Incomplete, invalid or malformed JSON payload.

.. http:put:: /passwordreset

   **Example request**:

   .. sourcecode:: http

      PUT /passwordreset HTTP/1.1
      Content-Type: application/json

      {
        "password": "t0pSecret",
        "token": "fdf1033a39a0ffae50784b44909a97bd"
      }

   :<json string password: A plain text password that will be set for this account.
   :<json string token: The one-time token sent via email.

   **Example response body**:

   .. sourcecode:: json

      {
        "account_id": "8138177c4fa45ce839d158374d1601c9"
      }

   :>json string account_id: The identifier of the newly created account.


   :statuscode 200: A new account password is set.
   :statuscode 401: Provided one-time token is invalid or expired.
   :statuscode 409: Account email address has changed since the one-time token was generated. You must request a new password reset token.





.. _Time-based One-Time Passwords: https://en.wikipedia.org/wiki/Time-based_One-time_Password
.. _Time-based One-Time Password: https://en.wikipedia.org/wiki/Time-based_One-time_Password
.. _base32: https://en.wikipedia.org/wiki/Base32
