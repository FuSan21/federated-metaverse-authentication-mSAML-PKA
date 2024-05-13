from fastapi import FastAPI
import uvicorn

from guestserver.models.visitors import create_visitors_db

import guestserver.database as _database
import guestserver.routers.visitors as _visitors


def create_guestserver():
    create_visitors_db()

    guestserver = FastAPI()

    return guestserver


guestserver = create_guestserver()

guestserver.include_router(_visitors.router, tags=["Visitor"])


@guestserver.get("/")
def root():
    return {"msg": "Federated Metaverse Guest Server"}


if __name__ == "__main__":
    uvicorn.run("guestserver.main:guestserver", host="localhost", port=9000, reload=True)
