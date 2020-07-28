import os
import tempfile
import time

import click
from tabulate import tabulate

from ..state.connection import state_connection
from ..state.device import device_state, Ios, Android
from ..state.filemanager import file_manager_state
from ..utils.helpers import sizeof_fmt

# variable used to cache entries from the ls-like
# commands used in the below helpers. only used
# by the _get_short_*_listing methods.
_ls_cache = {}


def cd(args: list) -> None:
    """
        Change the current working directory of the device.

        While this method does not actually change any directories,
        it simply updates the value in the file_manager_state property
        that keeps record of the current directory.

        Before changing directories though, some checks are performed
        on the device to at least ensure that the destination directory
        exists.

        :param args:
        :return:
    """

    if len(args) <= 0:
        click.secho('Usage: cd <destination directory>', bold=True)
        return

    path = args[0]
    current_dir = pwd()

    # nothing to do
    if path == '.':
        return

    # moving one directory back
    if path == '..':

        split_path = os.path.split(current_dir)

        # nothing to do if we are already at root
        if len(split_path) == 1:
            return

        new_path = ''.join(split_path[:-1])
        click.secho(new_path, fg='green', bold=True)

        file_manager_state.cwd = new_path

        return

    # if we got an absolute path, check if the path
    # actually exists, and then cd to it if we can
    if os.path.isabs(path):

        # assume the path does not exist by default
        does_exist = False

        # check for existence based on the runtime
        if device_state.device_type == Ios:
            does_exist = _path_exists_ios(path)

        if device_state.device_type == Android:
            does_exist = _path_exists_android(path)

        # if we checked with the device that the path exists
        # and it did, update the state manager, otherwise
        # show an error that the path may be invalid
        if does_exist:
            click.secho(path, fg='green', bold=True)

            file_manager_state.cwd = path
            return

        else:
            click.secho('Invalid path: `{0}`'.format(path), fg='red')

    # directory is not absolute, tack it on at the end and
    # see if its legit.
    else:

        proposed_path = device_state.device_type.path_seperator.join([current_dir, path])

        # assume the proposed_path does not exist by default
        does_exist = False

        # check for existence based on the runtime
        if device_state.device_type == Ios:
            does_exist = _path_exists_ios(proposed_path)

        if device_state.device_type == Android:
            does_exist = _path_exists_android(proposed_path)

        # if we checked with the device that the path exists
        # and it did, update the state manager, otherwise
        # show an error that the path may be invalid
        if does_exist:
            click.secho(proposed_path, fg='green', bold=True)

            file_manager_state.cwd = proposed_path
            return

        else:
            click.secho('Invalid path: `{0}`'.format(proposed_path), fg='red')


def path_exists(path: str) -> bool:
    """
        Checks if a path exists on remote device.

        :param path:
        :return:
    """

    if device_state.device_type == Ios:
        return _path_exists_ios(path)

    if device_state.device_type == Android:
        return _path_exists_android(path)


def _path_exists_ios(path: str) -> bool:
    """
        Checks an iOS device if a path exists.

        :param path:
        :return:
    """

    api = state_connection.get_api()
    return api.ios_file_exists(path)


def _path_exists_android(path: str) -> bool:
    """
        Checks an Android device if a path exists.

        :param path:
        :return:
    """

    api = state_connection.get_api()
    return api.android_file_exists(path)


def pwd(args: list = None) -> str:
    """
        Return the current working directory.

        If a record exists in the filemanager state, that directory
        is returned. Else, an environment specific call is made to
        the device to determine the directory it considers itself
        to be working from.

        :param args:
        :return:
    """

    if file_manager_state.cwd is not None:
        return file_manager_state.cwd

    if device_state.device_type == Ios:
        return _pwd_ios()

    if device_state.device_type == Android:
        return _pwd_android()


def pwd_print(args: list = None) -> None:
    """
        Prints the current working directory.

        :param args:
        :return:
    """

    click.secho('Current directory: {0}'.format(pwd()))


def _pwd_ios() -> str:
    """
        Execute a Frida hook that gets the current working
        directory from an iOS device.

        :return:
    """

    api = state_connection.get_api()
    cwd = api.ios_file_cwd()

    # update the file_manager state's cwd
    file_manager_state.cwd = cwd

    return cwd


def _pwd_android() -> str:
    """
        Execute a Frida hook that gets the current working
        directory from an Android device.

        :return:
    """

    api = state_connection.get_api()
    cwd = api.android_file_cwd()

    # update the file_manager state's cwd
    file_manager_state.cwd = cwd

    return cwd


def ls(args: list) -> None:
    """
        Get a directory listing for a path on a device.
        If no path is provided, the current working directory is used.

        :param args:
        :return:
    """

    # check if we have received a path to ls for.
    if len(args) <= 0:
        path = pwd()
    else:
        path = args[0]
        if not os.path.isabs(path):
            path = device_state.device_type.path_seperator.join([pwd(), path])

    # based on the runtime, execute the correct ls method.
    if device_state.device_type == Ios:
        _ls_ios(path)

    if device_state.device_type == Android:
        _ls_android(path)


def _ls_ios(path: str) -> None:
    """
        List files implementation for iOS.

        See:
            http://www.stanford.edu/class/cs193p/cgi-bin/drupal/system/files/lectures/09_Data.pdf

        :param path:
        :return:
    """

    api = state_connection.get_api()
    data = api.ios_file_ls(path)

    def _get_key_if_exists(attribs, key):
        """
            Small helper to grab keys where some may or may
            not exist in the file attributes.

            :param attribs:
            :param key:
            :return:
        """

        if key in attribs:
            return attribs[key]

        return 'n/a'

    def _humanize_size_if_possible(size: str) -> str:
        """
            Small helper method used to 'humanize' file sizes
            if the file size is not recorded as 'n/a'

            :param size:
            :return:
        """

        return sizeof_fmt(int(size)) if size != 'n/a' else 'n/a'

    # if the directory was readable, dump the filesystem listing
    # and attributes to screen.
    click.secho(tabulate(
        [[
            _get_key_if_exists(file_data['attributes'], 'NSFileType').replace('NSFileType', ''),
            _get_key_if_exists(file_data['attributes'], 'NSFilePosixPermissions'),
            _get_key_if_exists(file_data['attributes'], 'NSFileProtectionKey').replace('NSFileProtection', ''),

            # file read / write permissions
            file_data['readable'],
            file_data['writable'],

            # owner name and uid
            _get_key_if_exists(file_data['attributes'], 'NSFileOwnerAccountName') + ' (' +
            _get_key_if_exists(file_data['attributes'], 'NSFileOwnerAccountID') + ')',

            # group name and gid
            _get_key_if_exists(file_data['attributes'], 'NSFileGroupOwnerAccountName') + ' (' +
            _get_key_if_exists(file_data['attributes'], 'NSFileGroupOwnerAccountID') + ')',

            _humanize_size_if_possible(_get_key_if_exists(file_data['attributes'], 'NSFileSize')),
            _get_key_if_exists(file_data['attributes'], 'NSFileCreationDate'),

            file_name,

        ] for file_name, file_data in data['files'].items()], headers=[
            'NSFileType', 'Perms', 'NSFileProtection', 'Read', 'Write', 'Owner', 'Group', 'Size', 'Creation', 'Name'
        ],
    )) if data['readable'] else None

    # handle the permissions summary for this directory
    click.secho('\nReadable: {0}  Writable: {1}'.format(data['readable'], data['writable']), bold=True)


def _ls_android(path: str) -> None:
    """
        Lit files implementation for Android devices.

        :param path:
        :return:
    """

    api = state_connection.get_api()
    data = api.android_file_ls(path)

    def _timestamp_to_str(stamp: str) -> str:
        """
            Small helper method to convert the timestamps we get
            from the Android filesystem to human readable ones.

            :param stamp:
            :return:
        """

        # convert the time to an integer
        stamp = int(stamp)

        if stamp > 0:
            return time.strftime('%Y-%m-%d %H:%M:%S GMT', time.gmtime(stamp / 1000.0))

        return 'n/a'

    click.secho(tabulate(
        [[
            'Directory' if file_data['attributes']['isDirectory'] else 'File',

            _timestamp_to_str(file_data['attributes']['lastModified']),

            # read / write permissions
            file_data['readable'],
            file_data['writable'],
            file_data['attributes']['isHidden'],

            sizeof_fmt(float(file_data['attributes']['size'])),

            file_name,

        ] for file_name, file_data in data['files'].items()], headers=[
            'Type', 'Last Modified', 'Read', 'Write', 'Hidden', 'Size', 'Name'
        ],
    )) if data['readable'] else None

    click.secho('\nReadable: {0}  Writable: {1}'.format(data['readable'], data['writable']), bold=True)


def download(args: list) -> None:
    """
        Downloads a file from a remote filesystem and stores
        it locally.

        This method is simply a proxy to the actual download methods
        used for the appropriate environment.

        :param args:
        :return:
    """

    if len(args) < 1:
        click.secho('Usage: file download <remote location> (optional: <local destination>)', bold=True)
        return

    # determine the source and destination file names.
    # if we didnt get a specification of where to dump the file,
    # assume the same name should be used locally.
    source = args[0]
    destination = args[1] if len(args) > 1 else os.path.basename(source)

    if device_state.device_type == Ios:
        _download_ios(source, destination)

    if device_state.device_type == Android:
        _download_android(source, destination)


def _download_ios(path: str, destination: str) -> None:
    """
        Download a file from an iOS filesystem and store it locally.

        :param path:
        :param destination:
        :return:
    """

    # if the path we got is not absolute, join it with the
    # current working directory
    if not os.path.isabs(path):
        path = device_state.device_type.path_seperator.join([pwd(), path])

    api = state_connection.get_api()

    click.secho('Downloading {0} to {1}'.format(path, destination), fg='green', dim=True)

    if not api.ios_file_readable(path):
        click.secho('Unable to download file. File is not readable.', fg='red')
        return

    if not api.ios_file_path_is_file(path):
        click.secho('Unable to download file. Target path is not a file.', fg='yellow')
        return

    click.secho('Streaming file from device...', dim=True)
    file_data = api.ios_file_download(path)

    click.secho('Writing bytes to destination...', dim=True)
    with open(destination, 'wb') as fh:
        fh.write(bytearray(file_data['data']))

    click.secho('Successfully downloaded {0} to {1}'.format(path, destination), bold=True)


def _download_android(path: str, destination: str) -> None:
    """
        Download a file from the Android filesystem and store it locally.

        :param path:
        :param destination:
        :return:
    """

    # if the path we got is not absolute, join it with the
    # current working directory
    if not os.path.isabs(path):
        path = device_state.device_type.path_seperator.join([pwd(), path])

    api = state_connection.get_api()

    click.secho('Downloading {0} to {1}'.format(path, destination), fg='green', dim=True)

    if not api.android_file_readable(path):
        click.secho('Unable to download file. Target path is not readable.', fg='red')
        return

    if not api.android_file_path_is_file(path):
        click.secho('Unable to download file. Target path is not a file.', fg='yellow')
        return

    click.secho('Streaming file from device...', dim=True)
    file_data = api.android_file_download(path)

    click.secho('Writing bytes to destination...', dim=True)
    with open(destination, 'wb') as fh:
        fh.write(bytearray(file_data['data']))

    click.secho('Successfully downloaded {0} to {1}'.format(path, destination), bold=True)


def upload(args: list) -> None:
    """
        Uploads a local file to the remote operating system.

        This method is just a proxy method to the real upload
        method used based on the runtime that is available.

        :param args:
        :return:
    """

    if len(args) < 1:
        click.secho('Usage: file upload <local source> (optional: <remote destination>)', bold=True)
        return

    source = args[0]
    destination = args[1] if len(args) > 1 else device_state.device_type.path_seperator.join(
        [pwd(), os.path.basename(source)])

    if device_state.device_type == Ios:
        _upload_ios(source, destination)

    if device_state.device_type == Android:
        _upload_android(source, destination)


def _upload_ios(path: str, destination: str) -> None:
    """
        Upload a file to a remote iOS filesystem.

        :param path:
        :param destination:
        :return:
    """

    if not os.path.isabs(destination):
        destination = device_state.device_type.path_seperator.join([pwd(), destination])

    api = state_connection.get_api()
    click.secho('Uploading {0} to {1}'.format(path, destination), fg='green', dim=True)

    # if we cant read the file, just stop
    if not api.ios_file_writable(os.path.dirname(destination)):
        click.secho('Unable to upload file. Destination is not writable.', fg='red')
        return

    click.secho('Reading source file...', dim=True)
    with open(path, 'rb') as f:
        data = f.read().hex()

    click.secho('Sending file to device for writing...', dim=True)
    api.ios_file_upload(destination, data)

    click.secho('Uploaded: {0}'.format(destination), dim=True)

    # unset the cache key for this directory so the next short listing
    # will have updated contents
    if os.path.dirname(destination) in _ls_cache:
        del _ls_cache[os.path.dirname(destination)]


def _upload_android(path: str, destination: str) -> None:
    """
        Upload a file to a remote Android filesystem.

        :param path:
        :param destination:
        :return:
    """

    if not os.path.isabs(destination):
        destination = device_state.device_type.path_seperator.join([pwd(), destination])

    api = state_connection.get_api()
    click.secho('Uploading {0} to {1}'.format(path, destination), fg='green', dim=True)

    # if we cant read the file, just stop
    if not api.android_file_writable(os.path.dirname(destination)):
        click.secho('Unable to upload file. Destination is not writable.', fg='red')
        return

    click.secho('Reading source file...', dim=True)
    with open(path, 'rb') as f:
        data = f.read().hex()

    click.secho('Sending file to device for writing...', dim=True)
    api.android_file_upload(destination, data)

    click.secho('Uploaded: {0}'.format(destination), dim=True)

    # unset the cache key for this directory so the next short listing
    # will have updated contents
    if os.path.dirname(destination) in _ls_cache:
        del _ls_cache[os.path.dirname(destination)]


def rm(args: list) -> None:
    """
        Remove a file from the remote filesystem.

        :param args:
        :return:
    """

    if len(args) < 1:
        click.secho('Usage: rm <target remote file>', bold=True)
        return

    target = args[0]

    if not os.path.isabs(target):
        target = device_state.device_type.path_seperator.join([pwd(), target])

    if not click.confirm('Really delete {0} ?'.format(target)):
        click.secho('Not deleting {0}'.format(target), dim=True)
        return

    if device_state.device_type == Ios:
        _rm_ios(target)

    if device_state.device_type == Android:
        _rm_android(target)


def _rm_android(t: str) -> None:
    """
        Removes a file from an Android device.

        :param t:
        :return:
    """

    api = state_connection.get_api()

    if not _path_exists_android(t):
        click.secho('{0} does not exist'.format(t), fg='red')
        return

    if api.android_file_delete(t):
        click.secho('{0} successfully deleted'.format(t), fg='green')

    # update the file system cache entry
    if os.path.dirname(t) in _ls_cache:
        del _ls_cache[os.path.dirname(t)]


def _rm_ios(t: str) -> None:
    """
        Removes a file from an iOS device.

        :param t:
        :return:
    """

    api = state_connection.get_api()

    if not _path_exists_ios(t):
        click.secho('{0} does not exist'.format(t), fg='red')
        return

    if api.ios_file_delete(t):
        click.secho('{0} successfully deleted'.format(t), fg='green')

    # update the file system cache entry
    if os.path.dirname(t) in _ls_cache:
        del _ls_cache[os.path.dirname(t)]


def cat(args: list):
    """
        Downloads a file from a remote filesystem and echos
        it's contents

        This method is simply a proxy to the relevant download methods
        that echoes the contents and cleans up after itself.

        :param args:
        :return:
    """

    if len(args) < 1:
        click.secho('Usage: file cat <remote location>', bold=True)
        return

    # determine the source and destination file names.
    # if we didnt get a specification of where to dump the file,
    # assume the same name should be used locally.
    source = args[0]
    _, destination = tempfile.mkstemp('.file')

    if device_state.device_type == Ios:
        _download_ios(source, destination)

    if device_state.device_type == Android:
        _download_android(source, destination)

    click.secho('====', dim=True)
    with open(destination, 'r', encoding='utf-8', errors='ignore') as f:
        print(f.read(), end='', )
    click.secho('====', dim=True)

    os.remove(destination)


def _get_short_ios_listing() -> list:
    """
        Get a shortened file and directory listing for
        iOS devices.

        :return:
    """

    # default to the pwd. this method is for tab
    # completions anyways.
    directory = pwd()

    # the response for this directory
    resp = []

    # check our cheap cache if we have a listing
    if directory in _ls_cache:
        return _ls_cache[directory]

    api = state_connection.get_api()
    data = api.ios_file_ls(directory)

    # loop the response, marking entries as either being
    # a file or a directory. this response will be stored
    # in the _ls_cache too.
    for name, attribs in data['files'].items():

        # attributes key contains the type
        attributes = attribs['attributes']

        # if the attributes dict does not have the file type,
        # just continue as we cant be sure what it is.
        if 'NSFileType' not in attributes:
            continue

        # append a tuple with name, type
        resp.append((name, 'directory' if attributes['NSFileType'] == 'NSFileTypeDirectory' else 'file'))

    # cache the response so its faster next time!
    _ls_cache[directory] = resp

    # grab the output lets seeeeee
    return resp


def _get_short_android_listing() -> list:
    """
        Get a shortened file and directory listing for
        Android devices.

        :return:
    """

    # default to the pwd. this method is for tab
    # completions anyways.
    directory = pwd()

    # the response for this directory
    resp = []

    # check our cheap cache if we have a listing
    if directory in _ls_cache:
        return _ls_cache[directory]

    api = state_connection.get_api()
    data = api.android_file_ls(directory)

    # loop the response, marking entries as either being
    # a file or a directory. this response will be stored
    # in the _ls_cache too.
    for name, attribs in data['files'].items():
        attributes = attribs['attributes']

        # append a tuple with name, type
        resp.append((name, 'directory' if attributes['isDirectory'] else 'file'))

    # cache the response so its faster next time!
    _ls_cache[directory] = resp

    # grab the output lets seeeeee
    return resp


def list_folders_in_current_fm_directory() -> dict:
    """
        Return folders in the current working directory of the
        Frida attached device.
    """

    resp = {}

    # get the folders based on the runtime
    if device_state.device_type == Ios:
        response = _get_short_ios_listing()

    elif device_state.device_type == Android:
        response = _get_short_android_listing()

    # looks like we landed in an unknown runtime.
    # just return.
    else:
        return resp

    # loop the response to get entries for the 'directory'
    # type.
    for entry in response:
        file_name, file_type = entry

        if file_type == 'directory':
            resp[file_name] = file_name

    return resp


def list_files_in_current_fm_directory() -> dict:
    """
        Return files in the current working directory of the
        Frida attached device.
    """

    resp = {}

    # check for existence based on the runtime
    if device_state.device_type == Ios:
        response = _get_short_ios_listing()

    elif device_state.device_type == Android:
        response = _get_short_android_listing()

    # looks like we landed in an unknown runtime.
    # just return.
    else:
        return resp

    # loop the response to get entries for the 'directory'
    # type.
    for entry in response:
        file_name, file_type = entry

        if file_type == 'file':
            resp[file_name] = file_name

    return resp
