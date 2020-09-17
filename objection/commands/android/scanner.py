import click
import requests

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
        
    #Now we've got the FireBase URL, lets request some data
    
