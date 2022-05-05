from flask import Flask, request, abort, render_template
from flask_cors import CORS, cross_origin

import logic

app = Flask(__name__)
keys = logic.generate_rsa_key_pairs(2048)
CORS(app)
CORS(app, resources={r"/*": {"origins": "*"}})


@app.route("/server/ticket")
@cross_origin()
def validate_tgt():
    try:
        tgt = request.form.get('tgt')
        iv = request.form.get('iv')
        data = request.form.get('data')

        if tgt is not None and data is not None and iv is not None:
            tgt = logic.decrypt_tgt(tgt, logic.unhexlify(iv))
            data = logic.decrypt_client_info(data, tgt['session_key'])

            if int(tgt['time']) - int(data['time']) <= 30 * 60000:
                if tgt['username'] == data['username']:
                    ticket = logic.create_ticket(data['username'], tgt['address'])
                    server_session = logic.encrypt_server_session_key(data['username'], tgt['session_key'])
                    return {"ticket": ticket, "server_session": server_session[0], "iv": server_session[1]}
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
