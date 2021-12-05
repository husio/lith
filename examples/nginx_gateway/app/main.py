import json
import urllib.request

import bottle

LITH_URL = "http://lith:8000/api"

@bottle.route("/")
def index():
    session_id = bottle.request.get_cookie("s")
    if session_id:
        req = urllib.request.Request(LITH_URL + "/sessions")
        req.add_header("authorization", "Bearer " + session_id)
        with urllib.request.urlopen(req) as resp:
            return """<!doctype html>
                <h1>Hello there!</h1>
                <p>
                    Here is your authentication information:
                    <pre><code>{}</code></pre>
                </p>
                <p>
                    <a href="/logout">Logout</a>
                </p>
            """.format(resp.read().decode('utf8'))

    return """<!doctype html>
        <h1>Hello stranger!</h1>
        <p>You are not authenticated</p>
        <a href="/auth/login/">Login</a>
    """

@bottle.route("/logout")
def logout():
    bottle.response.delete_cookie("s")
    return bottle.redirect("/")


if __name__ == "__main__":
    bottle.run(host="0.0.0.0", port=8000)
