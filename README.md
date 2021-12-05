[![Go](https://github.com/husio/lith/actions/workflows/go.yml/badge.svg)](https://github.com/husio/lith/actions/workflows/go.yml) | [Quick Start](#quick-start) | [Examples](#examples)

# Lith


Lith is a service that integrates with your application to provide
authentication functionality. It is small, fast, self-contained and easy to
configure.


## Features

* **Account registration** with email verification and a secure password setup.
* **Account recovery** through password reset email message.
* **Session management** including creation, introspection, expiration and revoking.
* **Permission management** by assigning permissions to each account.
* **Two-factor** authentication using Time-based One-Time Password.
* **Admin Panel** for managing the application.
* **HTML and JSON** interfaces to integrate with your application.
* **Open Source**
* **Since dependency** (SMTP server), single static binary.


## Quick start

Lith is a standalone service that can be incorporated into your setup in
several ways. It takes only 3 steps to have it running locally, ready to serve traffic.

In order to run lith, you must create a configuration file. You can generate
one using `print-config` command:

    lith print-config > conf.toml

Second configuration step is to add an administrator account that will be able
to login to the admin panel.

    lith -conf conf.toml useradd -email my.email@domain.com -password "t0psecret" -groups=1,2

Finally, you can run the application and serve HTTP traffic:

    lith -conf conf.toml serve

Visit http://localhost:8000/admin/ and login with your admin account.

`examples/` directory contains demo application that show how integration with
lith can be done.


## Examples

- [Nginx gateway, services routing based on the path](examples/nginx_gateway/),
- [A standalone Go application with an embedded reverse proxy to Lith](examples/go_reverseproxy/),
- [A single page application using Lith JSON API](examples/js_spa/),
