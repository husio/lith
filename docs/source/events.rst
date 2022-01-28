Events
======

Events allow external services to receive information about various changes in the lith application.

For example, every time a new account is created, ``account-registered`` event is published. If you want to a certain operation when a new account is registered, ``account-registered`` event is what you are looking for.

Currently, the only way for an external service to subscribe is to handle webhooks.


Sinks
-----

File system store
^^^^^^^^^^^^^^^^^

During the local development it is easier to use the ``fs`` event sink backend. Every published event is then written to a specified directory::

    EventSinkBackend = "fs"

    [EventSinkFilesystem]
      Dir = "/tmp/lith_events"


Ignore all events
^^^^^^^^^^^^^^^^^

If you decide you do not care about publshed events, you can configure to drop all of them by setting the backend to ``dropall`` sink::

    EventSinkBackend = "dropall"


Webhook
^^^^^^^

Add to your configuration file the following lines::

    EventSinkBackend = "webhook"

    [EventSinkWebhook]
      URL = "https://SERVICE_ADDRESS"
      Secret = "A-LONG-RANDOM-STRING"

Secret should be shared with the subscriber in order to verify each request signature.

Each event contains a `signature` header that is computed the following way::

    signature = hmac(sha256, secret + json_payload)

Each JSON serialiezd payload contains a `now` attribute that is set the the request creation time. Assumming that wall clocks that all services are using are well synchronized, make sure to not accept requests older or newer than 30 seconds. This timestamp is included to prevent replay attacks.


Event objects
-------------

Each event is a JSON serialized object.

**Event**
  * **id** string: A unique identifier, that should be used for events deduplication.
  * **kind** string: The type name of the event.
  * **created_at** RFC 3339 string: The wall clock time of when the event happened.
  * **payload** object: Event-type specific data. See below evens list.


Example event:

.. code-block:: json

    {
      "kind": "account-registered",
      "id": "db296c7c9ab90dfda90a8a6b3b45c6b3",
      "created_at": "2022-01-16T08:06:22Z",
      "payload": {
        "account_id": "5b992459fbe3252c8aff50faeed3c2c3",
        "email": "alice@example.com"
      }
    }



account-registered
^^^^^^^^^^^^^^^^^^

``account-registered`` event is emitted when a new Account is created.

Event payload attributes:
  * **account_id** string: Created Account ID.
  * **email** string: Created Account email address.


session-created
^^^^^^^^^^^^^^^

``session-created`` event is emitted when an authentication session is created.

Event payload attributes:
  * **account_id** string: Created Account ID.
