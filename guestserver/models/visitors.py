from sqlalchemy import Column, Integer, String, Boolean, Enum
from sqlalchemy.orm import relationship

import guestserver.database.connection as _database


class Visitors(_database.Base):
    __tablename__ = "visitors"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, index=True)
    is_active = Column(Boolean, default=False)
    status = Column(Enum("pending", "accepted", "rejected", name="status"), default="pending")
    public_key = Column(String(1024))

class Blacklist(_database.Base):
    __tablename__ = "blacklist"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, index=True)

def create_visitors_db():
    _database.Base.metadata.create_all(_database.engine)