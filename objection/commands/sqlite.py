import binascii
import os
import sqlite3

import click
from tabulate import tabulate

from ..commands.filemanager import download, upload, pwd
from ..state.sqlite import sqlite_manager_state


def _get_connection():
    return sqlite3.connect(sqlite_manager_state.temp_file)


def status(args):
    db_file = sqlite_manager_state.file

    if db_file:
        click.secho(
            'Connected using file: {0} (locally cached at: {1})'.format(db_file, sqlite_manager_state.temp_file),
            fg='green')
        return

    click.secho('Not connected to any file', fg='blue')


def connect(args):
    if len(args) <= 0:
        click.secho('Usage: sqlite connect <remote_file>', bold=True)
        return

    if sqlite_manager_state.is_connected():
        click.secho('Already connected to a db. Disconnecting...', fg='yellow')
        sqlite_manager_state.cleanup()

    db_location = args[0]
    local_path = sqlite_manager_state.get_cache_dir()

    # update the file path too. this will make is_connected return true
    sqlite_manager_state.file = db_location

    # update the full remote path for future syncs
    sqlite_manager_state.full_remote_file = db_location \
        if os.path.isabs(db_location) else os.path.join(pwd(), db_location)

    click.secho('Caching local copy of database file...', fg='green')
    download([db_location, local_path])

    click.secho('Validating SQLite database format', dim=True)
    with open(local_path, 'rb') as f:
        header = f.read(16)
        header = binascii.hexlify(header)

    if header != b'53514c69746520666f726d6174203300':
        click.secho('File does not appear to be a SQLite3 db. Try downloading and manually inspecting this one.',
                    fg='red')
        sqlite_manager_state.cleanup()
        return

    click.secho('Connected to SQLite database at: {0}'.format(db_location), fg='green')


def disconnect(args=None):
    if sqlite_manager_state.is_connected():
        click.secho('Disconnecting database: {0}'.format(sqlite_manager_state.file))
        sqlite_manager_state.cleanup()
        return

    click.secho('Not connected to a database.')


def schema(args=None):
    if not sqlite_manager_state.is_connected():
        click.secho('Connect using sqlite connect first!', fg='red')
        return

    query = 'select sql from sqlite_master where type = \'table\''
    execute(query.split(' '))


def execute(args):
    if not sqlite_manager_state.is_connected():
        click.secho('Connect using sqlite connect first!', fg='red')
        return

    if len(args) <= 1:
        click.secho('Usage: sqlite execute select <query>', bold=True)
        return

    query = ' '.join(args)

    connection = _get_connection()

    try:

        with connection:
            results = connection.execute(query)

    except (sqlite3.OperationalError, sqlite3.Warning, sqlite3.Error) as e:

        click.secho('Error: {0}'.format(e.message), fg='red')
        return

    click.secho(tabulate(results), bold=True)

    for row in results:
        click.secho(row, bold=True)


def sync(args=None):
    if not sqlite_manager_state.is_connected():
        click.secho('Connect using sqlite connect first!', fg='red')
        return

    upload([sqlite_manager_state.temp_file, sqlite_manager_state.full_remote_file])
    click.secho('Databse sync complete')
