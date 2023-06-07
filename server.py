import traceback
import pyodbc

from flask import Flask, request, jsonify
from flask_cors import CORS
from waitress import serve
from loguru import logger
from Helpers.SQL import SQLHelper
from Helpers.JWT import JWTManager

app = Flask(__name__)
PORT = 3535
CORS(app)

server = 'ip'
database = 'database'
username = 'username'
password = "password"

conn_str = f'DRIVER={{SQL Server}};SERVER={server};DATABASE={database};UID={username};PWD={password}'
conn = pyodbc.connect(conn_str)

sql_helper = SQLHelper(conn)

secret_key = 'topsecretverysecretkey'
algorithm = 'HS256'

jwt_manager = JWTManager(secret_key, algorithm)


@app.route('/')
def hello_world():
    return 'Hello World!'

def check_token_and_get_user_id(request, getter = 'email'):
    token = request.headers.get('Authorization')
    decoded_token = jwt_manager.verify_token(token.split(" ")[1])

    if not decoded_token:
        return jsonify({'message': 'Invalid token'}), 401

    return decoded_token[getter]


@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data['email']
        password = data['password']
        passwordHash = sql_helper.get_password_by_email(email)


        if passwordHash == password:
            id = sql_helper.get_user_id_by_email(email)
            payload = {
                'id': id,
                'email': email
            }
            payload = jwt_manager.create_payload(payload, 60)
            token = jwt_manager.generate_token(payload)
            return jsonify({'token': token}), 200
        else:
            return jsonify({'message': 'Invalid credentials'}), 401

    except Exception as e:
        return jsonify({'message': str(e)}), 500


@app.route('/add_user', methods=['POST'])
def add_user():
    try:
        data = request.get_json()
        email = data['email']
        password = data['password']
        public_key = data['public_key']

        if not email or not password or not public_key:
            return jsonify({'message': 'Invalid request'}), 400

        sql_helper.add_user(email, password, public_key)

        return jsonify({'message': 'User added successfully'}), 200

    except Exception as e:
        return jsonify({'message': str(e)}), 500


@app.route('/save_message', methods=['POST'])
def save_message():
    try:
        sender_id = check_token_and_get_user_id(request, "id")
        if not sender_id:
            return jsonify({'message': 'Invalid token'}), 401

        data = request.get_json()
        receiver_id = data['receiver_id']
        message = data['message']
        sql_helper.save_message(sender_id, receiver_id, message)
        return jsonify({'message': 'Message saved successfully'}), 200

    except Exception as e:
        return jsonify({'message': str(e)}), 500


@app.route('/get_messages', methods=['GET'])
def get_messages():
    try:
        user_id = check_token_and_get_user_id(request, "id")

        if not user_id:
            return jsonify({'message': 'Invalid token'}), 401

        receiver_id = request.args.get('receiver_id')
        page = request.args.get('page')
        if not receiver_id:
            return jsonify({'message': 'Receiver ID is required'}), 400

        if not page:
            page = 1

        sql_helper.conn.cursor().close()
        messages = sql_helper.get_messages(user_id, receiver_id, page)

        return jsonify({'messages': messages}), 200

    except Exception as e:
        print(e)
        return jsonify({'message': str(e)}), 500


@app.route('/last_message', methods=['GET'])
def last_message():
    try:
        user_id = check_token_and_get_user_id(request)

        if not user_id:
            return jsonify({'message': 'Invalid token'}), 401

        receiver_id = request.args.get('receiver_id')

        if not receiver_id:
            return jsonify({'message': 'Receiver ID is required'}), 400

        last_message = sql_helper.get_last_message(user_id, receiver_id)

        return jsonify({'messages': last_message}), 200

    except Exception as e:
        return jsonify({'message': str(e)}), 500

@app.route('/get_public_key', methods=['GET'])
def get_public_key():
    try:
        email = request.args.get('email')
        if not email:
            return jsonify({'message': 'User ID is required'}), 400

        public_key = sql_helper.get_public_key_by_username(email)

        if not public_key:
            return jsonify({'message': 'Public key not found'}), 404

        return jsonify({'public_key': public_key}), 200

    except Exception as e:
        print(e)
        return jsonify({'message': str(e)}), 500


@app.route('/add_contact', methods=['POST'])
def add_contact():
    try:
        user_id = check_token_and_get_user_id(request, "id")

        if not user_id:
            return jsonify({'message': 'Invalid token'}), 401

        contact_id = request.json.get('contact_id')
        print(user_id, contact_id)

        if not contact_id:
            return jsonify({'message': 'Contact ID is required'}), 400

        sql_helper.add_person_to_contacts(user_id, contact_id)

        return jsonify({'message': 'Contact added successfully'}), 200

    except Exception as e:
        print(e)
        return jsonify({'message': str(e)}), 500


@app.route('/remove_contact', methods=['POST'])
def remove_contact():
    try:
        decoded = check_token_and_get_user_id(request)

        if decoded:
            user_id = decoded['id']

            data = request.get_json()
            contact_id = data['contact_id']

            sql_helper.remove_contact(user_id, contact_id)

            return jsonify({'message': 'Contact removed successfully'}), 200
        else:
            return jsonify({'message': 'Unauthorized'}), 401

    except Exception as e:
        return jsonify({'message': str(e)}), 500


@app.route('/get_contacts', methods=['GET'])
def get_contacts():
    try:
        user_id = check_token_and_get_user_id(request,"id")
        if not user_id:
            return jsonify({'message': 'Invalid token'}), 401

        contacts = sql_helper.get_contacts(user_id)

        return jsonify({'contacts': contacts}), 200

    except Exception as e:
        return jsonify({'message': str(e)}), 500


@app.route('/verify_token', methods=['GET'])
def verify_token():
    try:
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Authorization token is missing'}), 401

        decoded_token = jwt_manager.verify_token(token)
        if not decoded_token:
            return jsonify({'message': 'Invalid token'}), 401

        return jsonify({'decoded_token': decoded_token}), 200

    except Exception as e:
        return jsonify({'message': str(e)}), 500


@app.errorhandler(404)
def page_not_found(e):
    return "Page not found", 404


@app.errorhandler(Exception)
def handle_exception(ex):
    trace = traceback.format_exc()
    logger.error(f"Error occurred while processing request to [{request.method}] {request.path}:\n{trace}")
    return str(ex), 500


def __init__() -> None:
    logger.info(f'Server listening on http://localhost:{PORT}')
    serve(app, host="0.0.0.0", port=PORT)


if __name__ == '__main__':
    __init__()

