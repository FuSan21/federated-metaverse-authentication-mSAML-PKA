from sqlalchemy.orm import Session

import guestserver.models.visitors as _models
import guestserver.schemas.visitors as _schemas

def get_requirements():
    return _schemas.Requirements(
        auth_type = "jwt",
        auth_algorithm = "RS256",
        challenge_type = "random_string"
    )

def is_blacklisted(db: Session, username: str):
    db_user = db.query(_models.Blacklist).filter(_models.Blacklist.username == username).first()
    if db_user is not None:
        return True
    return False

def already_in_session(db: Session, username: str):
    db_user = db.query(_models.Visitors).filter(_models.Visitors.username == username).first()
    if db_user is None:
        return False
    elif db_user.status == "rejected":
        return False
    return True

def is_accepted(db: Session, username: str):
    db_user = db.query(_models.Visitors).filter(_models.Visitors.username == username).first()
    if db_user is None:
        return False
    elif db_user.status == "accepted":
        return True
    return False


def start_session(db: Session, username: str, status: str):
    db_visitor = db.query(_models.Visitors).filter(_models.Visitors.username == username).first()
    if db_visitor is not None:
        db_visitor.status = status
        db.commit()
        db.refresh(db_visitor)
    else:
        db_visitor = _models.Visitors(username=username, status=status)
        db.add(db_visitor)
        db.commit()
        db.refresh(db_visitor)
    return 1
    
def update_public_key(db: Session, username: str, public_key: str):
    db_visitor = db.query(_models.Visitors).filter(_models.Visitors.username == username).first()
    db_visitor.public_key = public_key
    db.commit()
    db.refresh(db_visitor)
    return 1

def get_public_key(db: Session, username: str):
    db_visitor = db.query(_models.Visitors).filter(_models.Visitors.username == username).first()
    return db_visitor.public_key