import binascii
import os
import tempfile

import click
import litecli
from litecli.main import LiteCli

from ..commands.filemanager import download, upload, pwd, path_exists


def modify_config(rc):
    """
        Monkey patches the LiteCLI config to toggle
        settings that make more sense for us.

        :param rc:
        :return:
    """

    c = real_get_config(rc)
    c['main']['less_chatty'] = 'True'
    c['main']['enable_pager'] = 'False'

    return c


real_get_config = litecli.main.get_config
litecli.main.get_config = modify_config


def cleanup(p) -> None:
    """
        Remove a cached SQLite db

        :param p:
        :return:
    """

    os.remove(p)


def _should_sync_once_done(args: list) -> bool:
    """
        Checks if --sync flag was provided.

        :param args:
        :return:
    """

    return '--sync' in args


def connect(args: list) -> None:
    """
        Connects to a SQLite database by downloading a copy of the database
        from the device and storing it locally in a temporary directory.

        :param args:
        :return:
    """

    if len(args) <= 0:
        click.secho('Usage: sqlite connect <remote_file> (optional: --sync)', bold=True)
        return

    db_location = args[0]
    _, local_path = tempfile.mkstemp('.sqlite')
    use_shm = False  # does Shared Memory temp file exist ?
    use_wal = False  # does Write-Ahead-Log temp file exist ?
    use_jnl = False  # does Journal temp file exist ?
    write_back_tmp_sqlite = False  # if enabled temporary DB files are re-uploaded, this has not been testes

    # update the full remote path for future syncs
    full_remote_file = db_location \
        if os.path.isabs(db_location) else os.path.join(pwd(), db_location)

    click.secho('Caching local copy of database file...', fg='green')
    download([db_location, local_path])
    if path_exists(full_remote_file + '-shm'):
        click.secho('... caching local copy of database "shm" file...', fg='green')
        download([db_location + '-shm', local_path + '-shm'])
        use_shm = True
    if path_exists(full_remote_file + '-wal'):
        click.secho('... caching local copy of database "wal" file...', fg='green')
        download([db_location + '-wal', local_path + '-wal'])
        use_wal = True
    if path_exists(full_remote_file + '-journal'):
        click.secho('... caching local copy of database "journal" file...', fg='green')
        download([db_location + '-journal', local_path + '-journal'])
        use_jnl = True

    click.secho('Validating SQLite database format', dim=True)
    with open(local_path, 'rb') as f:
        header = f.read(16)
        header = binascii.hexlify(header)

    if header != b'53514c69746520666f726d6174203300':
        click.secho('File does not appear to be a SQLite3 db. Try downloading and manually inspecting this one.',
                    fg='red')
        cleanup(local_path)
        return

    click.secho('Connected to SQLite database at: {0}'.format(db_location), fg='green')

    # boot the litecli prompt
    lite = LiteCli(prompt='SQLite @ {} > '.format(db_location))
    lite.connect(local_path)
    lite.run_cli()

    if _should_sync_once_done(args):
        click.secho('Synchronizing changes back...', dim=True)
        upload([local_path, full_remote_file])
        # re-uploading temp sqlite files has not been tested and thus is disabled by default
        if write_back_tmp_sqlite:
            if use_shm:
                upload([local_path + '-shm', full_remote_file + '-shm'])
            if use_wal:
                upload([local_path + '-wal', full_remote_file + '-wal'])
            if use_jnl:
                upload([local_path + '-journal', full_remote_file + '-journal'])
    else:
        click.secho('NOT synchronizing changes back to device. Use --sync if you want that.', fg='green')

    # maak skoon
    cleanup(local_path)
    if use_shm:
        cleanup(local_path + '-shm')
    if use_wal:
        cleanup(local_path + '-wal')
    if use_jnl:
        cleanup(local_path + '-journal')
