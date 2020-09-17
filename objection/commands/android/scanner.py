import click
import requests
import re

from objection.state.connection import state_connection

def firebase(args: list) -> None:
    """
        Search for a Firebase Database and check if it's leaking data.

        :param args:
        :return:
    """
    api = state_connection.get_api()
    try:
        fbdb = api.android_get_fb_database()
        click.secho('Scanning FireBase DB: {0}'.format(fbdb), fg='green')
        click.secho('Note: If the DB is exposed, it may take a while to download', fg='red')
        response = requests.get(fbdb + '/.json')
        if response.status_code == 401:
            click.secho('Firebase DB is not leaking data', fg='green')
        elif response.status_code == 200:
            click.secho('Firebase DB is leaking data!', fg='red')
            if len(response.text) < 1000:
                click.secho('Size: {:,.0f}'.format(len(response.text)) + "B", fg='red')
            elif len(response.text) >= 1000 and len(response.text) < 1000000:
                click.secho('Size: {:,.0f}'.format(len(response.text)/float(1<<10)) + "KB", fg='red')
            elif len(response.text) >= 1000000:
                click.secho('Size: {:,.0f}'.format(len(response.text)/float(1<<20)) + "MB", fg='red')
        else:
            click.secho('Something weird happened. Please report the issue.', fg='red')
    except:
        click.secho('Application doesn''t make use of FireBase', fg='red')
        
def apikeys(args: list) -> None:
    """
        Search for Firebase Cloud Messaging API Keys.
        Ref: https://abss.me/posts/fcm-takeover/

        :param args:
        :return:
    """
    api = state_connection.get_api()
    output = []
    output = api.android_get_api_keys()
    
    # Firebase Cloud Messaging Web API Key
    pattern =  r'AIzaSy[0-9A-Za-z_-]{33}'
    # Firebase Cloud Messaging Server Key 
    pattern2 = r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'

    data = '{"registration_ids":["ABC"]}'

    for x in output:
        if re.search(pattern2, x):
            # Now lets create the request to validate the keys
            # If the keys validate, they are server keys and can be used to
            # send messages
            headers = {
                'Authorization': 'key={0}'.format(x),
                'Content-Type': 'application/json',
            }
            response = requests.post('https://fcm.googleapis.com/fcm/send', headers=headers, data=data)
            if response.status_code == 200:
                click.secho('FCM Server Key: {0}'.format(x) + ' - [VALID]', fg='green')
            elif response.status_code == 401:
                click.secho('FCM Server Key: {0}'.format(x) + ' - [INVALID]', fg='red')
        if re.search(pattern, x):
            # Now lets create the request to validate the keys
            # If the keys validate, they are server keys and can be used to
            # send messages
            headers = {
                'Authorization': 'key={0}'.format(x),
                'Content-Type': 'application/json',
            }
            response = requests.post('https://fcm.googleapis.com/fcm/send', headers=headers, data=data)
            if response.status_code == 200:
                click.secho('Legacy FCM Server Key: {0}'.format(x) + ' - [VALID]', fg='green')
            elif response.status_code == 401:
                click.secho('Web API Key: {0}'.format(x) + ' - [Nothing to do here]', fg='red')

        
