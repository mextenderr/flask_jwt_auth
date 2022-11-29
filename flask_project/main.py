from datetime import datetime, timezone

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException
import jwt
from functools import wraps

def auth_required(endpoint_method):
    """
    Should be used to decorate http endpoints which must only be accessed by logged-in users.
    Redirects to the endpoint method if:
        - Request has a jwt token provided in its 'x-access-token' header.
        - And that token is succesfully decoded with the 'HS256' algorithm.
    """

    @wraps(endpoint_method)
    def validate_jwt_token(*args, **kwargs):

        try:
            token = request.headers['x-access-token']
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])

            return endpoint_method(*args, **kwargs)

        except jwt.ExpiredSignatureError:
            return jsonify(message="Session time out"), 401

        except (KeyError, jwt.InvalidTokenError) as error:
            print(error)
            return jsonify(message="Unauthorized, please login"), 401

    return validate_jwt_token


app = Flask(__name__)
app.config.update(SECRET_KEY='verysecrettt')

@app.errorhandler(HTTPException)
def http_exception_handler(exception: HTTPException):
    return jsonify({
        "error": exception.description
    }), exception.code


@app.post('/login')
def main_get():
    request_data = request.get_json()

    given_username = request_data["username"]
    given_password = request_data["password"]

    if given_username == "user" and given_password == "pass":

        token = jwt.encode(
            {"exp": datetime.now(tz=timezone.utc)},
            key=app.config['SECRET_KEY'],
            algorithm='HS256'
        )

        return jsonify(token=token)

    else:
        return jsonify(message="Invalid auth, please try again.")


@app.post('/user')
@auth_required
def main_post():
    return jsonify("Accessed with jwt auth!")


app.run()
