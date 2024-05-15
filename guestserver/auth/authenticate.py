import jwt
from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from guestserver.database.connection import get_dbx
from guestserver.services.visitors import get_public_key

class AuthHandler():
    security = HTTPBearer()
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    def decode_access_token(self, token):
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            username = payload["iss"]
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Signature has expired")
        except jwt.InvalidTokenError as e:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        with get_dbx() as db:
            public_key = get_public_key(db=db, username=username)

        if public_key is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        jwt_public_key=load_pem_public_key(public_key.encode(), backend=default_backend())
        
        try:
            payload = jwt.decode(token, jwt_public_key, algorithms=["RS256"])
            if payload["sub"] != "access_token":
                raise HTTPException(status_code=401, detail="Invalid token")
            return payload["iss"]
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Signature has expired")
        except jwt.InvalidTokenError as e:
            raise HTTPException(status_code=401, detail="Invalid token")

    def auth_access_wrapper(
        self, auth: HTTPAuthorizationCredentials = Security(security)
    ):
        return self.decode_access_token(auth.credentials)
