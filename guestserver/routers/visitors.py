from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
import requests

import guestserver.database.connection as _database
import guestserver.services.visitors as _visitors
import guestserver.schemas.visitors as _schemas

conn_db = Depends(_database.get_db)

router = APIRouter()

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