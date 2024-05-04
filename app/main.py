from fastapi import FastAPI
import uvicorn

from app.models.users import create_users_db

import app.database as _database
import app.routers.users as _users


def create_app():
    create_users_db()

    app = FastAPI()

    return app


app = create_app()

app.include_router(_users.router, tags=["User"])


@app.get("/")
def root():
   return {"msg":"Federated Metaverse Authentication Server"}


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="localhost", port=8000, reload=True)
