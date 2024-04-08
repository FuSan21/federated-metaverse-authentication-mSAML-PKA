import requests
import http.client
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64

DEVICE_ID = "34567"
MAINSERVERADDRESS = "localhost:8000"
BIOMETRIC = "1234"


def validateCertificate():
    return True


def getBiometricsConfirmation():
    print("Please confirm your biometrics [PIN]: ")
    biometric = input()
    if biometric == BIOMETRIC:
        print("Biometrics Confirmed")
        return True
    else:
        print("Failed to confirm biometrics")
        return False


def sign_challenge(challenge):
    # Load the private key
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)

    # Sign the challenge
    signature = private_key.sign(
        challenge,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )

    return signature


def generateResponse(response, mainServerAddress):
    print("Generating Response")
    deviceidhash = hash(DEVICE_ID)
    data = {
        "deviceidhash": deviceidhash,
        "pass_username": response["pass_username"],
    }
    print(f"Challenge: {response["challenge"]}")
    challenge = response["challenge"].encode("utf-8")
    signature = sign_challenge(challenge)
    signature = base64.b64encode(signature).decode("utf-8")
    data["signature"] = signature

    postresponse = requests.post(f"http://{mainServerAddress}/auth", json=data)

    if postresponse.status_code == 200:
        print("Response Sent Successfully")
    else:
        print("Failed to send response")
        printHttpStatus(postresponse.status_code)


def biometricAuth(response, mainServerAddress):
    authenticRespose = validateCertificate()
    if authenticRespose:
        biometricVerified = getBiometricsConfirmation()
        if biometricVerified:
            generateResponse(response, mainServerAddress)
    else:
        print("Failed to validate certificate")


def printHttpStatus(status_code):
    try:
        status_description = http.client.responses[status_code]
        print(f"Status Code: {status_code} - {status_description}")
    except KeyError:
        print(f"Invalid status code: {status_code}")


def deviceIntriginityCheck():
    if DEVICE_ID == "34567":
        print("Device Intriginity Check Passed")
    else:
        print("Device Intriginity Check Failed")
        print("Disabling Secured Mode")
        exit()


def loginRequest(userName, deviceID, mainServerAddress, guestServerAddress):
    print("Starting Login Process")
    print("Enabling Secured Mode")
    deviceIntriginityCheck()
    print("Requesting Login to Metaworld Server")
    print(
        f"http://{mainServerAddress}/access?username={userName}&deviceID={deviceID}&serverAddress={guestServerAddress}"
    )
    response = requests.get(
        f"http://{mainServerAddress}/access?username={userName}&deviceID={deviceID}&serverAddress={guestServerAddress}"
    )
    if response.status_code == 200:
        biometricAuth(response.json(), mainServerAddress)
    else:
        print("Login Failed")
        printHttpStatus(response.status_code)
        print("Disabling Secured Mode")


if __name__ == "__main__":
    userName = "user1"
    guestServerAddress = "localhost:8000"
    loginRequest(userName, DEVICE_ID, MAINSERVERADDRESS, guestServerAddress)
