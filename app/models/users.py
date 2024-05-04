from sqlalchemy import Column, String, Integer, Boolean, ForeignKey
from sqlalchemy.orm import relationship

import app.database.connection as _database


class User(_database.Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, index=True)
    is_active = Column(Boolean, default=True)
    challenges = relationship("Challenge", back_populates="user")

class Challenge(_database.Base):
    __tablename__ = "challenges"
    id = Column(Integer, primary_key=True, index=True)
    pass_username = Column(String(255), unique=True, index=True)
    deviceidhash = Column(String(255))
    public_key = Column(String(1024))
    challenge = Column(String(255))
    username = Column(String(255), ForeignKey('users.username'))
    user = relationship("User", back_populates="challenges")

def create_users_db():
    _database.Base.metadata.create_all(_database.engine)
