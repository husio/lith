[![Go](https://github.com/husio/lith/actions/workflows/go.yml/badge.svg)](https://github.com/husio/lith/actions/workflows/go.yml) | [Quick Start](#quick-start) | [Examples](#examples)

# Lith


Lith is an authentication service that integrates with your application. It is
small, fast, self-contained and easy to configure.


## Features

* **Account registration** with email verification and a secure password setup.
* **Account recovery** through password reset email message.
* **Session management** including creation, introspection, expiration and revoking.
* **Permission management** by assigning permissions to each account.
* **Two-factor** authentication using Time-based One-Time Password.
* **Admin Panel** for managing the application.
* **HTML and JSON** interfaces to integrate with your application.
* **Open Source**
* **Single dependency** (SMTP server), single static binary.


## Quick start

Lith is a standalone service that can be incorporated into your setup in
several ways. To run an example, execute `make run-demo`.

## Examples

- [Nginx gateway, services routing based on the path](examples/nginx_gateway/)
- [A standalone Go application with an embedded reverse proxy to Lith](examples/go_reverseproxy/)
- [A single page application using Lith JSON API](examples/js_spa/)
