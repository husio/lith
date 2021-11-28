[![Go](https://github.com/husio/lith/actions/workflows/go.yml/badge.svg)](https://github.com/husio/lith/actions/workflows/go.yml)

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
* **No dependencies**, single static binary.


## Quick start

Lith is a standalone service that can be incorporated into your setup in
several ways. It takes only 3 steps to have it running locally, ready to serve traffic.

In order to run lith, you must create a configuration file. You can generate
one using `print-config` command:

    lith print-config > conf.toml

Please edit the generated `conf.toml` file and set `Secret`. You can generate
a decent value using the below command:

    cat /dev/urandom | tr -dc 'a-zA-Z0-9_\-()[]{}!@#$%^&*' | fold -w 64 | head -n 1

Second configuration step is to add an administrator account that will be able
to login to the admin panel.

    lith -conf conf.toml useradd -email my.email@domain.com -password "t0psecret" -groups=1,2

Finally, you can run the application and serve HTTP traffic:

    lith -conf conf.toml serve

Visit http://localhost:8000/admin/ and login with your admin account.

`examples/` directory contains demo application that show how integration with
lith can be done.
