from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
import requests
import jwt

import guestserver.database.connection as _database
import guestserver.services.visitors as _visitors
import guestserver.schemas.visitors as _schemas
import guestserver.auth.authenticate as _auth

auth_handler = _auth.AuthHandler()
conn_db = Depends(_database.get_db)

router = APIRouter()

def get_jwt_public_key(
    db: Session = conn_db
):
    auth: HTTPAuthorizationCredentials = Security(HTTPBearer())
    try:
        payload = jwt.decode(auth.credentials, options={"verify_signature": False})
        username = payload["iss"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Signature has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    return _visitors.get_public_key(db=db, username=username)
    
@router.get("/remoteaccess", response_model=_schemas.Requirements, status_code=201)
def remoteaccess(username: str, request: Request, db: Session = conn_db):
    if _visitors.is_blacklisted(db=db, username=username):
        raise HTTPException(status_code=401, detail="You have been blacklisted from the world")
    if _visitors.already_in_session(db=db, username=username):
        raise HTTPException(status_code=401, detail="You are already in a session")

    _visitors.start_session(db=db, username=username, status="pending")
    return _visitors.get_requirements()


@router.get("/accept", status_code=201)
def accept(username: str, db: Session = conn_db):
    if not _visitors.already_in_session(db=db, username=username):
        raise HTTPException(status_code=401, detail="You are not in a session")
    _visitors.start_session(db=db, username=username, status="accepted")
    server_address = username.split("@")[-1]
    request = f"http://{server_address}/jwt_public_key"
    response = requests.get(request)
    if response.status_code != 200:
        raise HTTPException(status_code=401, detail="Failed get jwt public key from the remote server")
    try:
        jwt_public_key = response.json().get("public_key")
    except Exception:
        raise HTTPException(status_code=401, detail="Failed get jwt public key from the remote server")
    _visitors.update_public_key(db=db, username=username, public_key=jwt_public_key)
    return {"message": "Sucess"}

@router.get("/visit", status_code=201)
def visit(
    db: Session = conn_db,
    username=Depends(auth_handler.auth_access_wrapper),
):
    if username is None:
        raise HTTPException(status_code=401, detail="not authorized")
    is_accepted = _visitors.is_accepted(db=db, username=username)
    if not is_accepted:
        raise HTTPException(status_code=401, detail="not authorized")
    return {"message": "Welcome to the world"}