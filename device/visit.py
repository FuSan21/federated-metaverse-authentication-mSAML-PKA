import requests

# Read access token from file
with open('./device/access_token.txt', 'r') as file:
    access_token = file.read().strip()

# Send request using access token
url = 'http://localhost:9000/visit'
headers = {'Authorization': f'Bearer {access_token}'}
response = requests.get(url, headers=headers)

# Check if token expired
if response.status_code == 401 and response.json().get('detail') == 'Signature has expired':
    # Read refresh token from file
    with open('./device/refresh_token.txt', 'r') as file:
        refresh_token = file.read().strip()

    # Refresh token
    refresh_url = 'http://localhost:8000/update_token'
    refresh_headers = {'Authorization': f'Bearer {refresh_token}'}
    refresh_response = requests.get(refresh_url, headers=refresh_headers)

    # Update access token with refreshed token
    if refresh_response.status_code == 200:
        access_token = refresh_response.json().get('access_token')

        # Save updated access token to file
        with open('./device/access_token.txt', 'w') as file:
            file.write(access_token)

        # Send request again with refreshed token
        headers = {'Authorization': f'Bearer {access_token}'}
        response = requests.get(url, headers=headers)
    else:
        print('Failed to refresh token')
        print(refresh_response.json())
else:
    print('Failed to send request')

print(response.json())