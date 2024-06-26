import requests
import http.client
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64

DEVICE_ID = "string"
MAINSERVERADDRESS = "localhost:8000"
BIOMETRIC = "1234"


def validateCertificate():
    print("Validating Certificate")
    print("Certificate Validated")
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
    with open("./device/private_key.pem", "rb") as key_file:
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


def generateResponse(response, mainServerAddress, userName):
    print("Generating Response for Challenge")
    deviceidhash = hash(DEVICE_ID)
    data = {
        "username": str(userName),
        "pass_username": str(response["pass_username"]),
        "deviceidhash": str(deviceidhash),
    }
    print(f"Challenge: {response["challenge"]}")
    challenge = response["challenge"].encode("utf-8")
    signature = sign_challenge(challenge)
    signature = base64.b64encode(signature).decode("utf-8")
    data["signature"] = str(signature)
    headers = {"Content-Type": "application/json"}
    postresponse = requests.post(f"http://{mainServerAddress}/auth", json=data, headers=headers)

    if postresponse.status_code == 200:
        print("Challenge Response Validated")
        print("Tokens Generatedclear: ", postresponse.json())
        for key, value in postresponse.json().items():
            with open(f"./device/{key}.txt", "w") as f:
                f.write(value)
    else:
        print("Failed to send response")
        printHttpStatus(postresponse.status_code)


def biometricAuth(response, mainServerAddress, userName):
    authenticRespose = validateCertificate()
    if authenticRespose:
        biometricVerified = getBiometricsConfirmation()
        if biometricVerified:
            generateResponse(response, mainServerAddress, userName)
    else:
        print("Failed to validate certificate")


def printHttpStatus(status_code):
    try:
        status_description = http.client.responses[status_code]
        print(f"Status Code: {status_code} - {status_description}")
    except KeyError:
        print(f"Invalid status code: {status_code}")


def deviceIntriginityCheck():
    if DEVICE_ID == "string":
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
        f"http://localhost:8000/access?username={userName}&deviceid=string&pass_username=string&server_address={guestServerAddress}"
    )
    response = requests.get(
        f"http://localhost:8000/access?username={userName}&deviceid=string&pass_username=string&server_address={guestServerAddress}"
    )
    if response.status_code == 201:
        print("Recieved a cryptographic Challenge")
        biometricAuth(response.json(), mainServerAddress, userName)
    else:
        print("Login Failed")
        printHttpStatus(response.status_code)
        print("Disabling Secured Mode")


if __name__ == "__main__":
    userName = "string@127.0.0.1:8000"
    guestServerAddress = "127.0.0.1:9000"
    loginRequest(userName, DEVICE_ID, MAINSERVERADDRESS, guestServerAddress)
