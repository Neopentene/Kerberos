from flask import Flask, request, abort, render_template
from flask_cors import CORS, cross_origin

import logic
import time

app = Flask(__name__)
keys = logic.generate_rsa_key_pairs(2048)
CORS(app)
CORS(app, resources={r"/*": {"origins": "*"}})


@app.route("/validate")
@cross_origin()
def validate_ticket():
    try:
        ticket = request.form.get('ticket')
        iv = request.form.get('iv')
        data = request.form.get('data')

        if ticket is not None and data is not None and iv is not None:
            ticket = logic.decrypt_ticket(ticket, logic.unhexlify(iv))
            data = logic.decrypt_client_info(data, ticket['session_key'])

            if int(ticket['time']) - int(data['time']) <= 30 * 60000:
                if ticket['username'] == data['username']:
                    timestamp, nonce = logic.encrypt_timestamp(str(data['time']), ticket['session_key'])
                    return {"timestamp": timestamp, "nonce": nonce}
        abort(404)
    except Exception:
        abort(404)


@app.route("/new/user")
@cross_origin()
def new_user():
    try:
        ticket = request.form.get('ticket')
        iv = request.form.get('iv')
        username = logic.decrypt_rsa_message(request.form.get('username').encode("utf-8"), keys)
        password = logic.decrypt_rsa_message(request.form.get('password').encode("utf-8"), keys)
        requester = request.form.get('requester')

        if ticket is not None and username is not None and password is not None and iv is not None:
            ticket = logic.decrypt_ticket(ticket, logic.unhexlify(iv))
            if ticket['username'] == requester:
                if ticket['time'] - time.time() * 1000 <= 24 * 60 * 60000:
                    return {"success": logic.create_new_user(username, password)}

        abort(404)
    except Exception:
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
#    app.run("127.0.0.1", 4500, True)
