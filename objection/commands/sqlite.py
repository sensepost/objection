import binascii
import os
import sqlite3

import click
from tabulate import tabulate

from ..commands.filemanager import download, upload, pwd
from ..state.sqlite import sqlite_manager_state


def _get_connection() -> sqlite3.Connection:
    """
        Returns a new connection to the currently locally
        cached sqlite file.

        :return:
    """

    return sqlite3.connect(sqlite_manager_state.temp_file)


def status(args: list) -> None:
    """
        Prints the status of the currently 'connected' (actually just cached)
        SQLite database.

        :param args:
        :return:
    """

    db_file = sqlite_manager_state.file

    if not db_file:
        click.secho('Not connected to any database file', fg='blue')

        return

    click.secho('Connected using file: {0} (locally cached at: {1})'.format(db_file, sqlite_manager_state.temp_file),
                fg='green')


def connect(args: list) -> None:
    """
        Connects to a SQLite database by downloading a copy of the database
        from the device and storing it locally in a temporary directory.

        :param args:
        :return:
    """

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


def disconnect(args: list = None) -> None:
    """
        Disconnects from the currently connected/cached SQLite database file
        by clearing the statemager and deleting the locally cached copy.

        :param args:
        :return:
    """

    if not sqlite_manager_state.is_connected():
        click.secho('Not connected to a database.', fg='yellow')
        return

    # confirm if the user wants to disconnect, warn about the need to sync
    if click.confirm(('Make sure you run \'sqlite sync\' if needed!\n'
                      'Are you sure you want to disconnect?')):
        click.secho('Disconnecting database: {0}'.format(sqlite_manager_state.file))

        # cleanup the connection and cached db
        sqlite_manager_state.cleanup()
        return


def schema(args=None):
    """
        Runs a query that dumps the current databases schema.

        :param args:
        :return:
    """

    if not sqlite_manager_state.is_connected():
        click.secho('Connect using sqlite connect first!', fg='red')
        return

    query = 'select sql from sqlite_master where type = \'table\''
    execute(query.split(' '))


def execute(args: list) -> None:
    """
        Executes a query against the locally cached SQLite database file.

        :param args:
        :return:
    """

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

        click.secho('Error: {0}'.format(e), fg='red')
        return

    table_data = []
    for row in results:
        row_data = [c.decode('utf-8', 'replace') if isinstance(c, bytes) else c for c in row]
        table_data.append(row_data)

    click.secho(tabulate(table_data), bold=True)


def sync(args: list = None) -> None:
    """
        Syncs the locally cached copy of the SQLite database with the
        remote location on a device.

        :param args:
        :return:
    """

    if not sqlite_manager_state.is_connected():
        click.secho('Connect using sqlite connect first!', fg='red')
        return

    upload([sqlite_manager_state.temp_file, sqlite_manager_state.full_remote_file])
    click.secho('Database sync complete')
