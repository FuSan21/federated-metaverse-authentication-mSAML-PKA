import jwt
from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
import random
import string
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key

class AuthHandler:
    security = HTTPBearer()
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    with open("./app/auth/private_key.pem", "rb") as key_file:
        jwt_private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
    with open("./app/auth/public_key.pem", "rb") as key_file:
        jwt_public_key = load_pem_public_key(key_file.read(), backend=default_backend())

    def get_jwt_public_key(self):
        return self.jwt_public_key

    def generate_pass_username(self, username):
        letters = string.ascii_lowercase
        return username + "." + ("".join(random.choice(letters) for i in range(10)))

    def generate_cryptographic_challenge(self, auth_type, auth_algorithm, challege_type):
        if challege_type != "random_string":
            raise HTTPException(status_code=400, detail="Unsupported challenge type")
        if auth_type != "jwt":
            raise HTTPException(status_code=400, detail="Unsupported auth type")
        if auth_algorithm != "RS256":
            raise HTTPException(status_code=400, detail="Unsupported auth algorithm")
        
        challenge = base64.b64encode(random.randbytes(32)).decode("utf-8")
        expiration = (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()
        return challenge,expiration+",jwt,RS256"

    def verify_cryptographic_challenge(self, challenge, challenge_details, signature, public_key):
        expiration = challenge_details.split(",")[0]
        if datetime.now(timezone.utc) > datetime.fromisoformat(expiration):
            raise HTTPException(status_code=401, detail="Challenge has expired")
        try:
            public_key = serialization.load_pem_public_key(public_key.encode())
            signature_bytes = base64.b64decode(signature)
            public_key.verify(
            signature_bytes,
            challenge.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        except Exception:
            return False
        return True

    def encode_token(self, username, type):
        payload = dict(iss=username, sub=type)
        to_encode = payload.copy()
        if type == "access_token":
            to_encode.update({"exp": datetime.now(timezone.utc) + timedelta(minutes=1)})
        else:
            to_encode.update({"exp": datetime.now(timezone.utc) + timedelta(hours=720)})

        return jwt.encode(to_encode, self.jwt_private_key, algorithm="RS256")

    def encode_login_token(self, username):
        access_token = self.encode_token(username, "access_token")
        refresh_token = self.encode_token(username, "refresh_token")

        login_token = dict(
            access_token=f"{access_token}", refresh_token=f"{refresh_token}"
        )
        return login_token

    def encode_update_token(self, username):
        access_token = self.encode_token(username, "access_token")

        update_token = dict(access_token=f"{access_token}")
        return update_token

    def decode_access_token(self, token):
        try:
            payload = jwt.decode(token, self.jwt_public_key, algorithms=["RS256"])
            if payload["sub"] != "access_token":
                raise HTTPException(status_code=401, detail="Invalid token")
            return payload["iss"]
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Signature has expired")
        except jwt.InvalidTokenError as e:
            raise HTTPException(status_code=401, detail="Invalid token")

    def decode_refresh_token(self, token):
        try:
            payload = jwt.decode(token, self.jwt_public_key, algorithms=["RS256"])
            if payload["sub"] != "refresh_token":
                raise HTTPException(status_code=401, detail="Invalid token")
            return payload["iss"]
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Sinature has expired")
        except jwt.InvalidTokenError as e:
            raise HTTPException(status_code=401, detail="Invalid token")

    def auth_access_wrapper(
        self, auth: HTTPAuthorizationCredentials = Security(security)
    ):
        return self.decode_access_token(auth.credentials)

    def auth_refresh_wrapper(
        self, auth: HTTPAuthorizationCredentials = Security(security)
    ):
        return self.decode_refresh_token(auth.credentials)
