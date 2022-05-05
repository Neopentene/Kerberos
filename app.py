from flask import Flask, request, abort, render_template
from flask_cors import CORS, cross_origin

import logic

app = Flask(__name__)
keys = logic.generate_rsa_key_pairs(2048)
CORS(app)
CORS(app, resources={r"/*": {"origins": "*"}})


@app.route("/<user>")
@cross_origin()
def validate_session(user):
    try:
        username, status = logic.check_user(user, keys)
        if status:
            tgt = logic.create_tgt(username, request.remote_addr)
            session_key = logic.encrypt_tgs_session_key(username)
            return {"tgt": tgt, "session_key": session_key[0], "iv": session_key[1], "salt": session_key[2]}
    except Exception:
        abort(404)
    abort(404)


@app.route("/public/key")
@cross_origin()
def public_key():
    try:
        key = keys.public_key().exportKey("PEM").decode("utf-8")
        return {"public_key": key}
    except Exception:
        abort(404)


@app.errorhandler(404)
def page_not_found_error(error):
    return render_template("404.html"), 404

# if __name__ == "__main__":
#    app.run("127.0.0.1", 45000, True)
