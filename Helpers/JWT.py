import jwt

from datetime import datetime, timedelta


class JWTManager:
    def __init__(self, secret_key, algorithm):
        self.secret_key = secret_key
        self.algorithm = algorithm

    def create_payload(self,payload:object, expiration_minutes):
        exp = datetime.utcnow() + timedelta(minutes=expiration_minutes)
        payload['exp'] = exp
        return payload

    def generate_token(self, payload):
        token = jwt.encode(payload, self.secret_key, self.algorithm)
        return token

    def verify_token(self, token):
        try:
            decoded = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return decoded
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def decode_token(self, token):
        try:
            decoded = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return decoded
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
