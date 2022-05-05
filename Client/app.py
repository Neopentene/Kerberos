import requests
from flask import Flask, abort, render_template, session, request
from flask_cors import CORS, cross_origin
from requests.exceptions import BaseHTTPError

import logic

app = Flask(__name__)
app.secret_key = logic.generate_secret_key_session()
keys = logic.generate_rsa_key_pairs(2048)
AS = "http://127.0.0.1:45000/"
TGS = "http://127.0.0.1:4500/"
ServiceServer = "http://127.0.0.1:4600/"
CORS(app)
CORS(app, resources={r"/*": {"origins": "*"}})


@app.route("/")
@cross_origin()
def kerberos():
    session.clear()
    session['public key'] = keys.public_key().exportKey("PEM").decode("utf-8")
    return render_template('login.html')


@app.route("/service")
@cross_origin()
def service():
    try:
        if 'public key' in session.keys() and session['public key'] is not None:
            if 'server_session' in session.keys() and 'ticket' in session.keys():
                session.pop('tgs_session')
                session.pop('tgs_public_key')
                session.pop('as_public_key')
                return render_template('newUser.html')
        abort(404)
    except Exception:
        abort(404)


@app.route("/api/TGS/host")
@cross_origin()
def tgs_host():
    try:
        if 'public key' in session.keys() and session['public key'] is not None:
            return TGS
        else:
            abort(404)
    except Exception:
        abort(404)


@app.route("/api/AS/host")
@cross_origin()
def as_host():
    try:
        if 'public key' in session.keys() and session['public key'] is not None:
            return AS
        else:
            abort(404)
    except Exception:
        abort(404)


@app.route("/api/service/host")
@cross_origin()
def service_host():
    try:
        if 'public key' in session.keys() and session['public key'] is not None:
            return ServiceServer
        else:
            abort(404)
    except Exception:
        abort(404)


@app.route("/api/public/key")
@cross_origin()
def publickey():
    if 'public key' in session.keys() and session['public key'] is not None:
        return {"public key": session['public key']}
    else:
        abort(404)


@app.route("/api/AS/public/key")
@cross_origin()
def as_public_key():
    try:
        if 'public key' in session.keys() and session['public key'] is not None:
            res = requests.get(AS + "public/key")
            key = res.json()
            session['as_public_key'] = key
            return key
        else:
            abort(404)
    except Exception:
        abort(404)


@app.route("/api/TGS/public/key")
@cross_origin()
def tgs_public_key():
    try:
        if 'public key' in session.keys() and session['public key'] is not None:
            res = requests.get(TGS + "public/key")
            key = res.json()
            session['tgs_public_key'] = key
            return key
        else:
            abort(404)
    except Exception:
        abort(404)


@app.route("/api/Service/public/key")
@cross_origin()
def service_public_key():
    try:
        if 'public key' in session.keys() and session['public key'] is not None:
            res = requests.get(ServiceServer + "public/key")
            key = res.json()
            session['service_public_key'] = key
            return key
        else:
            abort(404)
    except Exception:
        abort(404)


@app.route("/api/encrypt/user/<value>")
@cross_origin()
def encrypt_username(value):
    try:
        session['user'] = value
        if 'public key' in session.keys() and 'as_public_key' in session.keys() and session['public key'] is not None:
            encrypted_username = logic.encrypt_rsa_message(value, session['as_public_key']['public_key'])
            return encrypted_username
        else:
            abort(404)
    except BaseHTTPError:
        abort(404)


@app.route("/api/encrypt/service/details")
@cross_origin()
def encrypt_service_username_password():
    try:
        username = request.args.get('username')
        password = request.args.get('password')
        if 'public key' in session.keys() and 'service_public_key' in session.keys() \
                and session['public key'] is not None:
            encrypted_username = logic.encrypt_rsa_message(username, session['service_public_key']['public_key'])
            encrypted_password = logic.encrypt_rsa_message(password, session['service_public_key']['public_key'])
            return {"username": encrypted_username, "password": encrypted_password}
        else:
            abort(404)
    except BaseHTTPError:
        abort(404)


@app.route("/api/AS/tgt/<username>")
@cross_origin()
def send_username(username):
    try:
        if 'public key' in session.keys() and session['public key'] is not None:
            res = requests.get(AS + username)
            tgt = res.json()
            session['tgt'] = tgt
            return tgt
        else:
            abort(404)
    except Exception:
        abort(404)


@app.route("/api/TGS/ticket/<user>")
@cross_origin()
def server_ticket(user):
    try:
        if 'public key' in session.keys() and session['public key'] is not None:
            if 'tgt' in session.keys() and 'tgs_session' in session.keys():
                if 'tgs_public_key' in session.keys():
                    tgt = session['tgt']['tgt']
                    params = {
                        "tgt": tgt[0],
                        "iv": tgt[1],
                        "data": logic.encrypt_timestamp_client(user, session['tgs_session'])
                    }
                    res = requests.get(TGS + 'server/ticket', data=params)
                    json_object = res.json()

                    if json_object is not None:
                        session['ticket'] = json_object
                        session.pop('tgt')
                    else:
                        raise ValueError()

                    return json_object['ticket'][0]
        abort(404)
    except Exception:
        abort(404)


@app.route("/api/service/new/user/<timestamp>", methods=['POST'])
@cross_origin()
def create_new_user(timestamp):
    try:
        encrypted_user_details = request.get_json()
        print(encrypted_user_details)
        if encrypted_user_details is None:
            raise ValueError()
        else:
            if 'public key' in session.keys() and session['public key'] is not None:
                if 'ticket' in session.keys() and 'server_session' in session.keys():
                    if 'service_public_key' in session.keys():
                        ticket = session['ticket']['ticket']
                        timestamp = logic.decrypt_server_timestamp(session['server_session'],
                                                                   timestamp, encrypted_user_details['nonce'])
                        if timestamp == str(session['timestamp']):
                            user_details_params = {
                                "username": encrypted_user_details['username'],
                                "password": encrypted_user_details['password'],
                                "ticket": ticket[0],
                                "iv": ticket[1],
                                "requester": session['user']
                            }
                            res = requests.get(ServiceServer + 'new/user', data=user_details_params)
                            response = res.json()
                            return response
                        else:
                            return {"success": False}
        abort(404)
    except Exception:
        abort(404)


@app.route("/api/service/validate/user")
@cross_origin()
def authenticate_user_to_service_server():
    try:
        if 'public key' in session.keys() and session['public key'] is not None:
            if 'ticket' in session.keys() and 'server_session' in session.keys():
                if 'service_public_key' in session.keys():
                    ticket = session['ticket']['ticket']
                    data = logic.encrypt_timestamp_client(session['user'], session['server_session'])
                    session['timestamp'] = data[1]
                    params = {
                        "ticket": ticket[0],
                        "iv": ticket[1],
                        "data": data[0]
                    }
                    res = requests.get(ServiceServer + '/validate', data=params)
                    json_object = res.json()
                    return json_object
        abort(404)
    except Exception:
        abort(404)


@app.route("/api/decrypt/tgt/session/<password>")
@cross_origin()
def decrypt_tgt(password):
    try:
        if 'public key' in session.keys() and 'tgt' in session.keys() and session['public key'] is not None:
            tgt = session['tgt']
            tgs_session = logic.decrypt_session(
                logic.generate_key_from_password(
                    password.encode("utf-8"),
                    session['tgt']['salt'].encode("utf-8")),
                tgt['session_key'], tgt['iv']
            )
            session['tgs_session'] = tgs_session
            return {"session": tgs_session}
        else:
            abort(404)
    except BaseHTTPError:
        abort(404)


@app.route("/api/decrypt/server/session")
@cross_origin()
def decrypt_ticket():
    try:
        if 'public key' in session.keys() and 'ticket' in session.keys() and session['public key'] is not None:
            ticket = session['ticket']
            server_session = logic.decrypt_server_session(session['tgs_session'], ticket['server_session'],
                                                          logic.unhexlify(ticket['iv']))
            session['server_session'] = server_session
            return {"server_session": server_session}
        else:
            abort(404)
    except BaseHTTPError:
        abort(404)


@app.errorhandler(404)
def page_not_found_error(error):
    return render_template("404.html"), 404

# if __name__ == "__main__":
#    app.run("192.168.0.102", 45000, True)
