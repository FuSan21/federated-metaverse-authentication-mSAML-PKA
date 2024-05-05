from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

import app.database.connection as _database
import app.services.users as _users
import app.schemas.users as _schemas
import app.auth.authenticate as _auth


auth_handler = _auth.AuthHandler()

conn_db = Depends(_database.get_db)

router = APIRouter()


@router.post("/register", status_code=201, response_model=_schemas.User)
def create_user(user: _schemas.UserCreate, db: Session = conn_db):
    db_user = _users.get_user_by_username(db=db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="The username is already used")
    user.pass_username = auth_handler.generate_pass_username(user.username)
    return _users.create_user(db=db, user=user)


@router.get("/access", response_model=_schemas.Challenge)
def access(
    username: str,
    deviceid: str,
    pass_username: str,
    server_address: str,
    db: Session = conn_db,
):
    db_user = _users.get_user_by_username(db=db, username=username)
    if db_user is None:
        raise HTTPException(status_code=401, detail="The user does not exist")
    if not _users.pass_username_exists(db=db, username=username, pass_username=pass_username):
        raise HTTPException(status_code=401, detail="Invalid pass username")
    if not _users.is_valid_device(db=db, pass_username=pass_username, deviceid=deviceid):
        raise HTTPException(status_code=401, detail="Invalid device")

    return _users.create_challenge(
        db=db,
        pass_username=pass_username,
        challenge=auth_handler.generate_cryptographic_challenge(),
    )


@router.post("/auth", response_model=_schemas.LoginToken)
def login_user(user: _schemas.Signature, db: Session = conn_db):
    db_user = _users.get_user_by_username(db=db, username=user.username)
    if db_user is None:
        raise HTTPException(status_code=401, detail="The user does not exist")
    if not _users.pass_username_exists(db=db, username=user.username, pass_username=user.pass_username):
        raise HTTPException(status_code=401, detail="Passkey does not exist")
    if not _users.has_challenge(db=db, pass_username=user.pass_username):
        raise HTTPException(status_code=401, detail="Challenge does not exist")
    
    is_verified = auth_handler.verify_cryptographic_challenge(
        challenge=_users.get_challenge(db=db, pass_username=user.pass_username),
        signature=user.signature,
        public_key=_users.get_public_key(db=db, pass_username=user.pass_username)
    )
    if not is_verified:
        raise HTTPException(status_code=401, detail="Authentication failed")
    return auth_handler.encode_login_token(user.username)


@router.get("/users", response_model=List[_schemas.User])
def read_user(
    skip: int = 0,
    limit: int = 10,
    db: Session = conn_db,
    username=Depends(auth_handler.auth_access_wrapper),
):
    if username is None:
        raise HTTPException(status_code=401, detail="not authorization")
    db_users = _users.get_users(db=db, skip=skip, limit=limit)
    return db_users


@router.get("/update_token", response_model=_schemas.UpdateToken)
def update_token(username=Depends(auth_handler.auth_refresh_wrapper)):
    if username is None:
        raise HTTPException(status_code=401, detail="not authorization")
    return auth_handler.encode_login_token(username)
