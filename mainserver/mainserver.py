from typing import Union
from fastapi import FastAPI, HTTPException, Request
import random
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
import json

CHALLENGE = None

OWNSERVER = "localhost:8000"
app = FastAPI()


def createCryptographicChallenge():
    challenge = random.randbytes(32)
    print(f"Challenge: {challenge}")
    return challenge


def authenticateUser(username: str, deviceidhash: int, signature: str):
    global CHALLENGE
    if CHALLENGE is None:
        raise HTTPException(status_code=400, detail="No challenge started")

    with open("users.json", "rb") as users_file:
        users = json.loads(users_file.read())
        if users["user1"]["privatekeyfile"]:
            public_key_file = users["user1"]["privatekeyfile"]
        else:
            raise HTTPException(status_code=400, detail="User not found")

    # Load the public key
    with open(f"users/{public_key_file}", "rb") as key_file:
        pubkey = serialization.load_pem_public_key(key_file.read())
    # Decode the base64 signature
    signature_bytes = base64.b64decode(signature)
    try:
        print(f"Crypto Challenge: {CHALLENGE}")
        # Verify the signature
        pubkey.verify(
            signature_bytes,
            CHALLENGE.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


@app.get("/")
def read_root():
    return {"Hello": "World"}


@app.get("/access")
async def access(username: str, deviceID: str, serverAddress: str):
    global CHALLENGE
    if serverAddress == OWNSERVER:
        CHALLENGE = createCryptographicChallenge()
        CHALLENGE = base64.b64encode(CHALLENGE).decode("utf-8")
        deviceidhash = hash(deviceID)
        return {
            "pass_username": username,
            "deviceidhash": deviceidhash,
            "challenge": CHALLENGE,
        }
    else:
        return {"error": "Invalid Server Address"}


@app.post("/auth")
async def response(request: Request):
    data = await request.json()
    print("Response Received")
    print(data)
    print(
        authenticateUser(data["pass_username"], data["deviceidhash"], data["signature"])
    )
    return {"status": "Response Received"}
