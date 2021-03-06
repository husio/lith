[![Go](https://github.com/husio/lith/actions/workflows/test.yml/badge.svg)](https://github.com/husio/lith/actions/workflows/test.yml)
[![Documentation Status](https://readthedocs.org/projects/lith/badge/?version=latest)](https://lith.readthedocs.io/?badge=latest)
[Demo](https://lith-demo.herokuapp.com/)


Lith is an authentication service. It is small, fast, self-contained and easy to configure.

Documentation is available at https://lith.readthedocs.io
Demo instance is available at https://lith-demo.herokuapp.com/

## Features summary

* **Open Source**
* **Account registration** with email verification and a secure password setup.
* **Account recovery** through password reset email message.
* **Session management** including creation, introspection, expiration and revoking.
* **Permission management** by assigning permissions to each account.
* **Two-factor** authentication using Time-based One-Time Password.
* **Admin Panel** for managing the application.
* **HTML and JSON** interfaces to integrate with your application.
* **Single dependency** (SMTP server), single static binary.


## Quick start

Lith is a standalone service that can be integrated in many ways. You can start a generic demo instance by executing `./run run-demo`.
For more specific setup examples, see [examples](#examples) section.

## Examples

- [Nginx gateway, services routing based on the path](examples/nginx_gateway/)
- [A standalone Go application with an embedded reverse proxy to Lith](examples/go_reverseproxy/)
- [A single page application using Lith JSON API](examples/js_spa/)

## Screenshorts

> a picture is worth a thousand words

<img alt="Login" src="screenshots/public_login.png" width="300px" align="left">
<img alt="Setup account password" src="screenshots/public_account_password.png" width="300px" align="left">
<img alt="Two Factor Authentication setup" src="screenshots/public_twofactor.png"  width="300px" align="left">
<img alt="Admin panel: Permission Groups" src="screenshots/admin_permissiongroups.png" width="300px" align="left">
