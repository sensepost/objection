import base64
import os
import time

import click
from tabulate import tabulate

from ..state.device import device_state
from ..state.filemanager import file_manager_state
from ..utils.frida_transport import FridaRunner
from ..utils.helpers import sizeof_fmt
from ..utils.templates import ios_hook, android_hook

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
        if device_state.device_type == 'ios':
            does_exist = _path_exists_ios(path)

        if device_state.device_type == 'android':
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

        proposed_path = os.path.join(current_dir, path)

        # assume the proposed_path does not exist by default
        does_exist = False

        # check for existence based on the runtime
        if device_state.device_type == 'ios':
            does_exist = _path_exists_ios(proposed_path)

        if device_state.device_type == 'android':
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


def _path_exists_ios(path: str) -> bool:
    """
        Checks an iOS device if a path exists.

        :param path:
        :return:
    """

    runner = FridaRunner()

    # populate the template with the path we want to work with
    runner.set_hook_with_data(ios_hook('filesystem/exists'), path=path)
    runner.run()

    return runner.get_last_message().exists


def _path_exists_android(path: str) -> bool:
    """
        Checks an Android device if a path exists.

        :param path:
        :return:
    """

    runner = FridaRunner()

    # populate the template with the path we want to work with
    runner.set_hook_with_data(android_hook('filesystem/exists'), path=path)
    runner.run()

    return runner.get_last_message().exists


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

    if device_state.device_type == 'ios':
        return _pwd_ios()

    if device_state.device_type == 'android':
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

    hook = ios_hook('filesystem/pwd')

    runner = FridaRunner()
    runner.run(hook=hook)

    response = runner.get_last_message()

    if not response.is_successful():
        raise Exception('Failed to get cwd')

    # update the file_manager state's cwd
    file_manager_state.cwd = response.cwd

    return response.cwd


def _pwd_android() -> str:
    """
        Execute a Frida hook that gets the current working
        directory from an Android device.

        :return:
    """

    hook = android_hook('filesystem/pwd')

    runner = FridaRunner()
    runner.run(hook=hook)

    response = runner.get_last_message()

    if not response.is_successful():
        raise Exception('Failed to get cwd')

    # update the file_manager state's cwd
    file_manager_state.cwd = response.cwd

    return response.cwd


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

    # based on the runtime, execute the correct ls method.
    if device_state.device_type == 'ios':
        _ls_ios(path)

    if device_state.device_type == 'android':
        _ls_android(path)


def _ls_ios(path: str) -> None:
    """
        List files implementation for iOS.

        See:
            http://www.stanford.edu/class/cs193p/cgi-bin/drupal/system/files/lectures/09_Data.pdf

        :param path:
        :return:
    """

    runner = FridaRunner()
    runner.set_hook_with_data(ios_hook('filesystem/ls'), path=path)

    # the ls method is an rpc export
    api = runner.rpc_exports()

    # get the directory listing
    data = api.ls()

    # cleanup the runner
    runner.unload_script()

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
    if data['readable']:

        table_data = []
        for file_name, file_data in data['files'].items():
            # extract the attributes
            attributes = file_data['attributes']

            table_data.append([
                _get_key_if_exists(attributes, 'NSFileType').replace('NSFileType', ''),
                _get_key_if_exists(attributes, 'NSFilePosixPermissions'),

                _get_key_if_exists(attributes, 'NSFileProtectionKey').replace('NSFileProtection', ''),

                # read / write permissions
                file_data['readable'],
                file_data['writable'],

                # owner name and uid
                _get_key_if_exists(attributes, 'NSFileOwnerAccountName') + ' (' +
                _get_key_if_exists(attributes, 'NSFileOwnerAccountID') + ')',

                # group name and gid
                _get_key_if_exists(attributes, 'NSFileGroupOwnerAccountName') + ' (' +
                _get_key_if_exists(attributes, 'NSFileGroupOwnerAccountID') + ')',

                _humanize_size_if_possible(_get_key_if_exists(attributes, 'NSFileSize')),
                _get_key_if_exists(attributes, 'NSFileCreationDate'),
                file_name,
            ])

        click.secho(tabulate(table_data,
                             headers=['NSFileType', 'Perms', 'NSFileProtection', 'Read',
                                      'Write', 'Owner', 'Group', 'Size', 'Creation', 'Name']))

    # handle the permissions summary for this directory
    permissions = {
        'readable': 'No',
        'writable': 'No'
    }

    if data['readable']:
        permissions['readable'] = 'Yes'

    if data['writable']:
        permissions['writable'] = 'Yes'

    click.secho('\nReadable: {0}  Writable: {1}'.format(permissions['readable'], permissions['writable']), bold=True)


def _ls_android(path: str) -> None:
    """
        Lit files implementation for Android devices.

        :param path:
        :return:
    """

    runner = FridaRunner()
    runner.set_hook_with_data(
        android_hook('filesystem/ls'), path=path)
    runner.run()

    # grab the output lets seeeeee
    response = runner.get_last_message()

    # ensure the response was successful
    if not response.is_successful():
        click.secho('Failed to get directory listing with error: {}'.format(response.error_reason))
        return

    # get the response data itself
    data = response.data

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

    # if the directory was readable, dump the filesystem listing
    # and attributes to screen.
    if data['readable']:

        table_data = []
        for file_name, file_data in data['files'].items():
            attributes = file_data['attributes']

            table_data.append([

                'Directory' if attributes['isDirectory'] else 'File',

                _timestamp_to_str(attributes['lastModified']),

                # read / write permissions
                file_data['readable'],
                file_data['writable'],
                attributes['isHidden'],

                sizeof_fmt(float(attributes['size'])),

                file_name,
            ])

        click.secho(tabulate(table_data,
                             headers=['Type', 'Last Modified', 'Read', 'Write', 'Hidden', 'Size', 'Name']))

    # handle the permissions summary for this directory
    permissions = {
        'readable': 'No',
        'writable': 'No'
    }

    if data['readable']:
        permissions['readable'] = 'Yes'

    if data['writable']:
        permissions['writable'] = 'Yes'

    click.secho('\nReadable: {0}  Writable: {1}'.format(permissions['readable'], permissions['writable']), bold=True)


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

    if device_state.device_type == 'ios':
        _download_ios(source, destination)

    if device_state.device_type == 'android':
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
        path = os.path.join(pwd(), path)

    # output about whats about to happen
    click.secho('Downloading {0} to {1}'.format(path, destination), fg='green', dim=True)

    # start a runner. going to use this a few times
    # for this method
    runner = FridaRunner()

    # check that the path is readable
    runner.set_hook_with_data(ios_hook('filesystem/readable'), path=path)

    # run the hook
    runner.run()

    # get the response message
    response = runner.get_last_message()

    # if we cant read the file, just stop
    if not response.is_successful() or not response.readable:
        click.secho('Unable to download file. File is not readable')
        return

    # check that its a file
    runner.set_hook_with_data(ios_hook('filesystem/is-type-file'), path=path)

    # run the hook
    runner.run()

    # get the response message
    response = runner.get_last_message()

    if not response.is_successful() or not response.is_file:
        click.secho('Unable to download file. Not a file.')
        return

    # run the download hook and get the file from
    # extra_data
    runner.set_hook_with_data(ios_hook('filesystem/download'), path=path)
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to download {}: {}'.format(path, response.error_reason))
        return

    file_data = response.get_extra_data()

    # finally, write the downloaded file to disk
    with open(destination, 'wb') as fh:
        fh.write(file_data)


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
        path = os.path.join(pwd(), path)

    # output about whats about to happen
    click.secho('Downloading {0} to {1}'.format(path, destination), fg='green', dim=True)

    # start a runner. going to use this a few times
    # for this method
    runner = FridaRunner()

    # check that the path is readable
    runner.set_hook_with_data(android_hook('filesystem/readable'), path=path)

    # run the hook
    runner.run()

    # get the response message
    response = runner.get_last_message()

    # if we cant read the file, just stop
    if not response.is_successful() or not response.readable:
        click.secho('Unable to download file. File is not readable')
        return

    # check that its a file
    runner.set_hook_with_data(android_hook('filesystem/is-type-file'), path=path)

    # run the hook
    runner.run()

    # get the response message
    response = runner.get_last_message()

    if not response.is_successful() or not response.is_file:
        click.secho('Unable to download file. Not a file.')
        return

    # run the download hook and get the file from
    # extra_data
    runner.set_hook_with_data(android_hook('filesystem/download'), path=path)

    # the download method is an rpc export
    api = runner.rpc_exports()

    # download the file
    data = api.download()

    # cleanup the runner
    runner.unload_script()

    file_data = bytearray(data)

    # finally, write the downloaded file to disk
    with open(destination, 'wb') as fh:
        fh.write(file_data)


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
    destination = args[1] if len(args) > 1 else os.path.join(pwd(), os.path.basename(source))

    if device_state.device_type == 'ios':
        _upload_ios(source, destination)

    if device_state.device_type == 'android':
        _upload_android(source, destination)


def _upload_ios(path: str, destination: str) -> None:
    """
        Upload a file to a remote iOS filesystem.

        :param path:
        :param destination:
        :return:
    """

    if not os.path.isabs(destination):
        destination = os.path.join(pwd(), destination)

    # output about whats about to happen
    click.secho('Uploading {0} to {1}'.format(path, destination), fg='green', dim=True)

    # start a runner. going to use this a few times
    # for this method
    runner = FridaRunner()

    # check that the path is readable
    runner.set_hook_with_data(
        ios_hook('filesystem/writable'), path=os.path.dirname(destination))

    # run the hook
    runner.run()

    # get the response message
    response = runner.get_last_message()

    # if we cant read the file, just stop
    if not response.is_successful() or not response.writable:
        click.secho('Unable to upload file. Destination is not writable')
        return

    # read the local file to upload, and base64 encode it
    with open(path, 'rb') as f:
        data = f.read()
        data = str(base64.b64encode(data), 'utf-8')  # the frida hook wants a raw string

    # prepare the upload hook
    runner.set_hook_with_data(
        ios_hook('filesystem/upload'), destination=destination, base64_data=data)

    # run the upload hook
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to upload {}: {}'.format(path, response.error_reason))
        return

    click.secho('Uploaded: {0}'.format(destination), dim=True)


def _upload_android(path: str, destination: str) -> None:
    """
        Upload a file to a remote Android filesystem.

        :param path:
        :param destination:
        :return:
    """

    if not os.path.isabs(destination):
        destination = os.path.join(pwd(), destination)

    # output about whats about to happen
    click.secho('Uploading {0} to {1}'.format(path, destination), fg='green', dim=True)

    # start a runner. going to use this a few times
    # for this method
    runner = FridaRunner()

    # check that the path is readable
    runner.set_hook_with_data(
        android_hook('filesystem/writable'), path=os.path.dirname(destination))

    # run the hook
    runner.run()

    # get the response message
    response = runner.get_last_message()

    # if we cant read the file, just stop
    if not response.is_successful() or not response.writable:
        click.secho('Unable to upload file. Destination is not writable')
        return

    # read the local file to upload, and base64 encode it
    with open(path, 'rb') as f:
        data = f.read()
        data = str(base64.b64encode(data), 'utf-8')  # the frida hook wants a raw string

    # prepare the upload hook
    runner.set_hook_with_data(
        android_hook('filesystem/upload'), destination=destination, base64_data=data)

    # run the upload hook
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to upload {}: {}'.format(path, response.error_reason))
        return

    click.secho('Uploaded: {0}'.format(destination), dim=True)


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

    # fetch a fresh listing
    runner = FridaRunner()
    runner.set_hook_with_data(ios_hook('filesystem/ls'), path=directory)

    # the ls method is an rpc export
    api = runner.rpc_exports()

    # get the directory listing
    data = api.ls()

    # cleanup the runner
    runner.unload_script()

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

    # fetch a fresh listing
    runner = FridaRunner()
    runner.set_hook_with_data(android_hook('filesystem/ls'), path=directory)
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        # cache an empty response as an error occurred
        _ls_cache[directory] = resp

        return resp

    # loop the response, marking entries as either being
    # a file or a directory. this response will be stored
    # in the _ls_cache too.
    for name, attribs in response.data['files'].items():
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
    if device_state.device_type == 'ios':
        response = _get_short_ios_listing()

    elif device_state.device_type == 'android':
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
    if device_state.device_type == 'ios':
        response = _get_short_ios_listing()

    elif device_state.device_type == 'android':
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
