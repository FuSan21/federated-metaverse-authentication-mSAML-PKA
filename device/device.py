import requests
import http.client

DEVICE_ID = "1234"
MAINSERVERADDRESS = "example.com"


def biometricAuth():
    pass


def printHttpStatus(status_code):
    try:
        status_description = http.client.responses[status_code]
        print(f"Status Code: {status_code} - {status_description}")
    except KeyError:
        print(f"Invalid status code: {status_code}")


def loginRequest(userName, deviceID, mainServerAddress, guestServerAddress):
    print("Starting Login Process")
    print("Enabling Secured Mode")
    print("Requesting Login to Metaworld Server")
    requests.get(
        f"http://{mainServerAddress}/access?username={userName}&deviceID={deviceID}&serverAddress={guestServerAddress}"
    )
    if requests.status_code == 200:
        biometricAuth()
    else:
        print("Login Failed")
        printHttpStatus(requests.status_code)
        print("Disabling Secured Mode")


if __name__ == "__main__":
    userName = "user1"
    guestServerAddress = "example2.com"
    loginRequest(userName, DEVICE_ID, MAINSERVERADDRESS, guestServerAddress)
