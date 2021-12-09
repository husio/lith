;(function() {
"use strict"

var lithApiUrl = "http://localhost:8000/api"

var Account = null


var Index = {
  oninit: function () {
    m.route.set("/login")
  },
  view: function () {
  },
}

var Login = {
  oninit: function () {
    Account = null
    this.form = {
      success: false,
      loading: false,
      require2fa: false,
      enabled2fa: null,
      error: null,
      email: "",
      password: "",
      code: "",
    }
  },
  view: function () {
    var info = null
    var form = this.form

    if (form.error) {
      if (form.error.code) {
        form.require2fa = true
      } else if (form.error) {
        info = m("div.infobox.red", form.error)
      } else {
        info = m("div.infobox.red", ["Cannot login. ", form.error])
      }
    }
    if (form.loading) {
      info = m("span", "♻️ loading...") // Good enough for loading.
    }
    if (Account) {
      info = m("div.infobox.green", "Successful login")
    }

    if (form.require2fa && !form.enabled2fa) {
      // TODO - we have email and password that are valid. Next step is to
      // submit two-factor secret together with code to enable two-factor
      // authentication and authenticate once more in order to get session.
      // Part of this is implemented in TwoFactor component.
      //
      // Too boring to implement.
    }

    if (form.require2fa) {
      return m("main", [
        m("h1", "Login - verify"),
        m("form", {
          onsubmit: function (e) {
            e.preventDefault()

            form.error = null
            form.loading = true

            m.request({
              method: "POST",
              url: lithApiUrl + "/sessions",
              body: {email: form.email, password: form.password, code: form.code},
            })
            .then(function (result) {
              form.error = null
              form.loading = false
              Account = result
              setTimeout(function() { m.route.set("/hello") }, 500)
            })
            .catch(function (xhr) {
              form.loading = false
              form.error = xhr.response.error
            })
          }
        }, [
          m("fieldset", [
            m("label", [
              "Two-Factor verification code",
              m("input[placeholder=6 digits][required]", {
                oninput: function (e) { form.code = e.target.value },
                value: form.code
              }),
            ]),
            info,
          ]),
          m("fieldset", [
            m("button[type=submit]", "Verify"),
          ]),
        ]),
      ])
    }

    return m("main", [
      m("h1", "Login"),
      m("form", {
        onsubmit: function (e) {
          e.preventDefault()

          form.error = null
          form.loading = true

          m.request({
            method: "POST",
            url: lithApiUrl + "/sessions",
            body: {email: form.email, password: form.password},
          })
          .then(function (result) {
            form.error = null
            form.loading = false
            Account = result
            setTimeout(function() { m.route.set("/hello") }, 500)
          })
          .catch(function (xhr) {
            form.loading = false
            form.error = xhr.response.error

            // 2fa is required but not enabled for this account.
            if (xhr.code === 403) {
              fomr.require2fa = true
              form.enabled2fa = false
            }
          })
        },
      },[
        m("fieldset", [
          m("label", [
            "Email",
            m("input[placeholder=Email][type=email][required]", {
              oninput: function (e) { form.email = e.target.value },
              value: form.email
            }),
          ]),
          m("label", [
            "Password",
            m("input[placeholder=Password][type=password][required]", {
              oninput: function (e) { form.password = e.target.value },
              value: form.password
            }),
          ]),
          info,
        ]),
        m("fieldset", [
          m("button[type=submit]", "Login"),
          " or ",
          m(m.route.Link, {href: "/register"}, "create an account"),
          ".",
        ]),
        m("fieldset", [
          m(m.route.Link, {href: "/reset-password"}, "Forgot your password?"),
        ]),
      ])
    ])
  }
}

var Hello = {
  oninit: function() {
    if (!Account) {
      m.route.set("/")
      return
    }

    this.has2fa = null
    var that = this
    m.request({
      method: "GET",
      url: lithApiUrl + "/twofactor",
      headers: {Authorization: "Bearer " + Account.session_id},
    })
    .then(function (result) {
      that.loading = false
      that.has2fa = result.enabled
    })
    .catch(function (xhr) {
      that.loading = false
      that.has2fa = undefined
    })
  },
  view: function () {
    if (!Account) {
      m.route.set("/")
      return
    }
    var info2fa = null
    if (this.has2fa) {
      info2fa = m("div.infobox.green", "Two-Factor authentication is enabled.")
    } else {
      info2fa = m("div", [
        "Two-Factor authentication is not enabled. ",
        m(m.route.Link, {href: "/twofactor"}, "Enable Two-Factor authenication"),
        ".",
      ])
    }
    return m("div", [
      m("h1", "Hello!"),
      m("div.infobox.blue", "You are authenticated. Below are the details of your authentication session."),
      m("p", ["Session ID: ", m("code.sessionid", Account.session_id)]),
      m("p", ["Account ID: ", m("code.accountid", Account.account_id)]),
      m("p", ["Permissions: ", Account.permissions.map(function (p) {
        return m("code.permission", p)
      })]),
      info2fa,
      m(m.route.Link, {href: "/logout"}, "Logout"),
    ])
  }
}

var Register = {
  oninit: function () {
    Register.form = {
      loading: false,
      error: null,
      complete: false,
      email: "",
    }
  },
  view: function () {
    var form = Register.form

    if (form.complete) {
      return m("main", [
        m("h1", "New account"),
        m("div.infobox.green", "Please check your email and follow instructions to complete the registration process."),
        m("p", ["You can close this tab."]),
      ])
    }

    var info = null
    if (form.loading) {
      info = m("span", "♻️ work in progress...") // Good enough for loading.
    }
    if (form.error) {
      info = m("div.infobox.red", form.error)
    }

    return m("main", [
      m("h1", "New account"),
      m("form", {
        onsubmit: function (e) {
          e.preventDefault()

          form.error = null
          form.loading = true

          m.request({
            method: "POST",
            url: lithApiUrl + "/accounts",
            body: {email: form.email},
          })
          .then(function (result) {
            form.error = null
            form.loading = false
            form.complete = true
          }, function(result) {
            form.error = JSON.stringify(result.response)
            form.loading = false
            form.complete = false
          })
          .catch(function (xhr) {
            form.loading = false
            form.error = xhr.response.error
          })
        },
      },[
        m("fieldset", [
          m("label", [
            "Email",
            m("input[type=email][required]", {
              oninput: function (e) { form.email = e.target.value },
              value: form.email
            }),
          ]),
          info,
        ]),
        m("button[type=submit]", "Register"),
      ])
    ])
  }
}

var RegisterComplete = {
  oninit: function(vnode) {
    this.state = {
      done: false,
      form: {
        passwordsDiffer: false,
        loading: false,
        error: null,
        complete: false,
        password: "",
        password_repeat: "",
        token: vnode.attrs.token,
      }
    }
  },
  view: function () {
    var form = this.state.form

    var info = null
    if (form.passwordsDiffer) {
      info = m("div.infobox.red", "Passwords are not the same.")
    } else if (form.error) {
      info = m("div.infobox.red", form.error)
    }

    if (!form.loading && form.complete) {
      return m("main", [
        m("h1", "New account"),
        m("div.infobox.green", "Registration complete."),
        m(m.route.Link, {href: "/login"}, "Login"),
      ])
    }

    return m("main", [
      m("h1", "New account"),
      m("form", {
        onsubmit: function (e) {
          e.preventDefault()

          form.passwordsDiffer = form.password !== form.password_repeat && (
            form.password !== "" && form.password_repeat !== ""
          )
          if (form.passwordsDiffer) {
            form.error = null
            return
          }

          form.error = null
          form.loading = true

          m.request({
            method: "PUT",
            url: lithApiUrl + "/accounts",
            body: {password: form.password, token: form.token},
          })
          .then(function (result) {
            form.error = null
            form.loading = false
            form.complete = true
          }, function(result) {
            form.error = JSON.stringify(result.response)
            form.loading = false
            form.complete = false
          })
          .catch(function (xhr) {
            form.loading = false
            form.error = xhr.response.error
          })
        },
      },[
        m("div", "Setup password for the account."),
        m("fieldset", [
          m("label", [
            "Password",
            m("input[type=password][required]", {
              oninput: function (e) {
                form.password = e.target.value
                form.passwordsDiffer = false
              },
              value: form.password
            }),
          ]),
          m("label", [
            "Password repeat",
            m("input[type=password][required]", {
              oninput: function (e) {
                form.password_repeat = e.target.value
                form.passwordsDiffer = false
              },
              value: form.password_repeat
            }),
          ]),
          info,
        ]),
        m("button[type=submit]", "Register"),
      ])
    ])
  },
}

var ResetPassword = {
  oninit: function() {
    ResetPassword.form = {
      error: null,
      complete: false,
      loading: false,
      email: "",
    }
  },
  view: function () {
    var form = ResetPassword.form

    if (form.complete) {
      return m("main", [
        m("h1", "Reset password"),
        m("div.infobox.green", "Please check your email and follow instructions to complete the password reset process."),
        m("p", ["You can close this tab."]),
      ])
    }

    return m("main", [
      m("h1", "Reset password"),
      m("form", {
        onsubmit: function (e) {
          e.preventDefault()

          form.error = null
          form.loading = true

          m.request({
            method: "POST",
            url: lithApiUrl + "/passwordreset",
            body: {email: form.email},
          })
          .then(function (result) {
            form.error = null
            form.loading = false
            form.complete = true
          })
          .catch(function (xhr) {
            form.loading = false
            form.error = xhr.response.error
          })
        },
      },[
        m("fieldset", [
          m("label", [
            "Email",
            m("input[type=email][required]", {
              oninput: function (e) { form.email = e.target.value },
              value: form.email
            }),
          ]),
        ]),
        m("button[type=submit]", "Submit"),
      ])
    ])
  },
}

var ResetPasswordComplete = {
  oninit: function(vnode) {
    ResetPasswordComplete.form = {
      error: null,
      loading: false,
      complete: false,
      token: vnode.attrs.token,
      password: "",
      password_repeat: "",
      passwordsDiffer: false,
    }
  },
  view: function () {
    var form = ResetPasswordComplete.form

    if (form.complete) {
      return m("main", [
        m("h1", "Reset password"),
        m("div.infobox.green", "Password has been updated."),
        m("p", [
          m(m.route.Link, {href: "/login"}, "Login"),
        ]),
      ])
    }

    var info = null
    if (form.passwordsDiffer) {
      info = m("div.infobox.red", "Passwords are not the same.")
    }
    if (form.loading) {
      info = m("span", "♻️ work in progress...") // Good enough for loading.
    }
    if (form.error) {
      info = m("div.infobox.red", form.error)
    }

    return m("main", [
      m("h1", "Reset password"),
      m("form", {
        onsubmit: function (e) {
          e.preventDefault()

          form.passwordsDiffer = form.password !== form.password_repeat && (
            form.password !== "" && form.password_repeat !== ""
          )

          if (form.passwordsDiffer) {
            return
          }

          form.error = null
          form.loading = true

          m.request({
            method: "PUT",
            url: lithApiUrl + "/passwordreset",
            body: {token: form.token, password: form.password},
          })
          .then(function (result) {
            form.error = null
            form.loading = false
            form.complete = true
          })
          .catch(function (xhr) {
            form.loading = false
            form.error = xhr.response.error
          })
        },
      },[
        m("fieldset", [
          m("label", [
            "Password",
            m("input[type=password][required]", {
              oninput: function (e) {
                form.password = e.target.value
                form.passwordsDiffer = false
              },
              value: form.password
            }),
          ]),
          m("label", [
            "Password repeat",
            m("input[type=password][required]", {
              oninput: function (e) {
                form.password_repeat = e.target.value
                form.passwordsDiffer = false
              },
              value: form.password_repeat
            }),
          ]),
          info,
        ]),
        m("button[type=submit]", "Save"),
      ])
    ])
  },
}


var TwoFactor = {
  oninit: function() {
    if (!Account) {
      return
    }

    var rand = new Uint8Array(16)
    crypto.getRandomValues(rand)
    var secret = b32(rand)
    this.uri = "otpauth://totp/" + Account.account_id + "?issuer=lith-spa-demo&secret=" + secret + "&digits=6",
    this.form = {
      error: null,
      loading: false,
      secret: secret,
      code: "",
    }

    this.loading = true
    this.has2fa = null

    var that = this
    m.request({
      method: "GET",
      url: lithApiUrl + "/twofactor",
      headers: {Authorization: "Bearer " + Account.session_id},
    })
    .then(function (result) {
      that.loading = false
      that.has2fa = result.enabled
    }, function (result) {
      that.loading = false
      that.has2fa = undefined
      that.form.error = JSON.stringify(result.response)
    })
    .catch(function (xhr) {
      that.loading = false
      that.has2fa = undefined
    })
  },
  view: function () {
    var form = this.form

    if (!Account) {
      return m("div.infobox.red", [
          "You must be authenticated. ",
          m(m.route.Link , {href: "/login"}, "Login"), " first."
      ])
    }

    if (this.loading) {
      return m("div.infobox.blue", "Fetching two factor information.")
    }

    if (this.has2fa) {
      return m("div.infobox.green", "Two-Factor authentication is enabled.")
    }

    var info
    if (form.error) {
      info = m("div.infobox.red", form.error)
    }

    return m("main", [
      m("p.infobox.blue", [
        "Please scan the code below and confirm with the code ",
        "in order to enable two-factor authentication."
      ]),
      m(QRCodePic, {content: this.uri}),
      m("form", {
        onsubmit: function (e) {
          e.preventDefault()
          form.error = null
          form.loading = true

          m.request({
            method: "POST",
            url: lithApiUrl + "/twofactor",
            headers: {Authorization: "Bearer " + Account.session_id},
            body: {secret: form.secret, code: form.code},
          })
          .then(function (result) {
            form.error = null
            form.loading = false
            m.route.set("/hello")
          }, function (result) {
            form.loading = false
            form.error = JSON.stringify(result.response)
          })
          .catch(function (xhr) {
            form.loading = false
            form.error = xhr.response.error
          })
        },
      },[
        m("label", [
          "Confirmation code",
          info,
          m("input[required][placeholder=6 digits]", {
            oninput: function (e) { form.code = e.target.value },
            value: form.code,
          }),
        ]),
        m("button[type=submit]", "Confirm"),
      ]),
    ])
  },
}

var QRCodePic = {
  oninit: function() {
    this.nodeID = "qrcode-" + parseInt(Math.random() * 1000000, 10)
  },
  oncreate: function (vnode) {
    var node = document.getElementById(this.nodeID)
    new QRCode(node, {
            text: vnode.attrs.content,
            width: vnode.attrs.width || 256,
            height: vnode.attrs.height || 256,
            colorDark : "#000000",
            colorLight : "#ffffff",
            correctLevel : QRCode.CorrectLevel.H
    })
  },
  view: function() {
    return m("div", {id: this.nodeID})
  },
}

var Logout = {
  oninit: function () {
    if (!Account) {
      m.route.set("/login")
    }

    var session_id = Account.session_id
    Account = null
    m.request({
      method: "DELETE",
      url: lithApiUrl + "/sessions",
      headers: {Authorization: "Bearer " + session_id},
    })
    .then(function () { m.route.set("/login") })
    .catch(function () { m.route.set("/login") })
  },
  view: function () {
  },
}

var routes = {
  "/": Index,
  "/login": Login,
  "/logout": Logout,
  "/twofactor": TwoFactor,
  "/hello": Hello,
  "/register": Register,
  "/register/complete/:token": RegisterComplete,
  "/reset-password": ResetPassword,
  "/reset-password/complete/:token": ResetPasswordComplete,
}

window.addEventListener("load", function() {
  m.route(document.getElementById("app"), "/", routes)
})


// Code from
// https://stefanoborini.com/base32-encoding-in-javascript/
function b32(s) {
  /* encodes a string s to base32 and returns the encoded string */
  var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  var parts = [];
  var quanta= Math.floor((s.length / 5));
  var leftover = s.length % 5;

  if (leftover != 0) {
    for (var i = 0; i < (5-leftover); i++) { s += '\x00'; }
    quanta += 1;
  }

  for (i = 0; i < quanta; i++) {
    parts.push(alphabet.charAt(s.charCodeAt(i*5) >> 3));
    parts.push(alphabet.charAt( ((s.charCodeAt(i*5) & 0x07) << 2)
      | (s.charCodeAt(i*5+1) >> 6)));
    parts.push(alphabet.charAt( ((s.charCodeAt(i*5+1) & 0x3F) >> 1) ));
    parts.push(alphabet.charAt( ((s.charCodeAt(i*5+1) & 0x01) << 4)
      | (s.charCodeAt(i*5+2) >> 4)));
    parts.push(alphabet.charAt( ((s.charCodeAt(i*5+2) & 0x0F) << 1)
      | (s.charCodeAt(i*5+3) >> 7)));
    parts.push(alphabet.charAt( ((s.charCodeAt(i*5+3) & 0x7F) >> 2)));
    parts.push(alphabet.charAt( ((s.charCodeAt(i*5+3) & 0x03) << 3)
      | (s.charCodeAt(i*5+4) >> 5)));
    parts.push(alphabet.charAt( ((s.charCodeAt(i*5+4) & 0x1F) )));
  }

  var replace = 0;
  if (leftover == 1) replace = 6;
  else if (leftover == 2) replace = 4;
  else if (leftover == 3) replace = 3;
  else if (leftover == 4) replace = 1;

  for (i = 0; i < replace; i++) parts.pop();
  for (i = 0; i < replace; i++) parts.push("=");

  return parts.join("");
}


}());
