import requests

# Read access token from file
with open('./device/access_token.txt', 'r') as file:
    access_token = file.read().strip()

print('Visiting the world using access token "' + access_token + '"')
# Send request using access token
url = 'http://localhost:9000/visit'
headers = {'Authorization': f'Bearer {access_token}'}
response = requests.get(url, headers=headers)

# Check if token expired
if response.status_code == 401 and response.json().get('detail') == 'Signature has expired':
    print('Access token expired')
    print('Attempting to refresh access token')
    # Read refresh token from file
    with open('./device/refresh_token.txt', 'r') as file:
        refresh_token = file.read().strip()

    # Refresh token
    refresh_url = 'http://localhost:8000/update_token'
    refresh_headers = {'Authorization': f'Bearer {refresh_token}'}
    refresh_response = requests.get(refresh_url, headers=refresh_headers)

    # Update access token with refreshed token
    if refresh_response.status_code == 200:
        print('Successfully refreshed access token')
        access_token = refresh_response.json().get('access_token')
        print('Saving new access token "' + access_token + '"')
        # Save updated access token to file
        with open('./device/access_token.txt', 'w') as file:
            file.write(access_token)

        # Send request again with refreshed token
        print('Visiting the world using access token "' + access_token + '"')
        headers = {'Authorization': f'Bearer {access_token}'}
        response = requests.get(url, headers=headers)
        print('Successfully visited the world')
        print(response.json())
    else:
        print('Failed to refresh token')
        print(refresh_response.json())
elif response.status_code == 201:
    print('Successfully visited the world')
    print(response.json())
else:
    print(response.status_code)
    print('Failed to visit the world')