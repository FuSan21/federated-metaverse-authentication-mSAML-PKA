from sqlalchemy.orm import Session

import app.models.users as _models
import app.schemas.users as _schemas

def has_passkey(db: Session, username: str, pass_username: str):
    db_user = get_user_by_username(db=db, username=username)
    for challenge in db_user.challenges:
        if challenge.pass_username == pass_username:
            return True
    return False

def is_valid_device(db: Session, pass_username: str, deviceid: str):
    db_user = db.query(_models.Challenge).filter(_models.Challenge.pass_username == pass_username).first()
    if db_user.deviceidhash == deviceid:
        return True
    return False

def has_challenge(db: Session, pass_username: str):
    db_user = db.query(_models.Challenge).filter(_models.Challenge.pass_username == pass_username).first()
    if db_user.challenge is not None:
        return True
    return False

def get_user_by_username(db: Session, username: str):
    return db.query(_models.User).filter(_models.User.username == username).first()

def pass_username_exists(db: Session, username: str, pass_username: str):
    db_user = db.query(_models.Challenge).filter(_models.Challenge.username == username).filter(_models.Challenge.pass_username == pass_username).first()
    if db_user is None:
        return False
    return True

def get_public_key(db: Session, pass_username: str):
    db_user = db.query(_models.Challenge).filter(_models.Challenge.pass_username == pass_username).first()
    return db_user.public_key

def get_challenge(db: Session, pass_username: str):
    db_challenge = db.query(_models.Challenge).filter(_models.Challenge.pass_username == pass_username).first()
    return db_challenge.challenge

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

    return _schemas.User(
        id=db_user.id,
        username=db_user.username,
        is_active=db_user.is_active,
        pass_username=db_challenge.pass_username,
        deviceidhash=db_challenge.deviceidhash,
    )


def create_challenge(db: Session, pass_username: str, challenge: str):
    db_challenge = (
        db.query(_models.Challenge)
        .filter(_models.Challenge.pass_username == pass_username)
        .first()
    )
    db_challenge.challenge = challenge
    db.commit()
    db.refresh(db_challenge)

    challenge = _schemas.Challenge(
        pass_username=db_challenge.pass_username,
        deviceidhash=db_challenge.deviceidhash,
        challenge=challenge,
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
