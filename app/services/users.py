from sqlalchemy.orm import Session
from sqlalchemy import desc

import app.models.users as _models
import app.schemas.users as _schemas


def get_user_by_username(db: Session, username: str):
    return db.query(_models.User).filter(_models.User.username == username).first()


def create_user(db: Session, user: _schemas.UserCreate):
    db_user = _models.User(username=user.username)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    db_challenge = _models.Challenge(
        pass_username=user.pass_username,
        deviceidhash=user.deviceidhash,
        public_key=user.public_key,
        username=user.username,
    )
    db.add(db_challenge)
    db.commit()
    db.refresh(db_challenge)

    return db_user, db_challenge


def create_challenge(db: Session, username: str, challenge: str):
    db_challenge = (
        db.query(_models.Challenge)
        .filter(_models.Challenge.username == username)
        .first()
    )
    db_challenge.challenge = challenge
    db.commit()
    challenge = _schemas.Challenge(
        pass_username=db_challenge.pass_username,
        deviceidhash=db_challenge.deviceidhash,
        challenge=db_challenge.challenge,
    )
    return challenge


def get_deviceidhash(db: Session, username: str):
    db_challenge = (
        db.query(_models.Challenge)
        .filter(_models.Challenge.username == username)
        .first()
    )
    return db_challenge.deviceidhash


def update_deviceidhash(db: Session, username: str, deviceidhash: str):
    db_user = get_user_by_username(db=db, username=username)
    db_user.deviceidhash = deviceidhash
    db.commit()
    return db_user


def get_users(db: Session, skip: int, limit: int):
    return db.query(_models.User).offset(skip).limit(limit).all()


def get_user(db: Session, user_id: int):
    return db.query(_models.User).filter(_models.User.id == user_id).first()
