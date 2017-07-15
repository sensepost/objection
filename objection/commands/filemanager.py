import base64
import os

import click
from tabulate import tabulate

from ..state.device import device_state
from ..state.filemanager import file_manager_state
from ..utils.frida_transport import FridaRunner
from ..utils.helpers import sizeof_fmt
from ..utils.templates import ios_hook


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

        runner = FridaRunner()

        # populate the template with the path we want to work with
        runner.set_hook_with_data(
            ios_hook('filesystem/exists'), path=path)
        runner.run()

        if runner.get_last_message().exists:
            click.secho(path, fg='green', bold=True)

            file_manager_state.cwd = path
            return
        else:
            click.secho('Invalid path: `{0}`'.format(path), fg='red')

    # directory is not absolute, tack it on at the end and
    # see if its legit.
    else:

        proposed_path = os.path.join(current_dir, path)

        runner = FridaRunner()

        # populate the template with the path we want to work with
        runner.set_hook_with_data(
            ios_hook('filesystem/exists'), path=proposed_path)
        runner.run()

        if runner.get_last_message().exists:
            click.secho(proposed_path, fg='green', bold=True)

            file_manager_state.cwd = proposed_path
            return
        else:
            click.secho('Invalid path: `{0}`'.format(proposed_path), fg='red')


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


def _pwd_android() -> None:
    """
        This would be the method to return the current working
        directory from an Android device.

        :return:
    """

    pass


def ls(args: list) -> None:
    """
        Get a directory listing for a path on a device.
        If no path is provided, the current working directory is used.

        :param args:
        :return:
    """

    # check if we have recevied a path to ls for.
    if len(args) <= 0:
        path = '.'
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

    if path == '.':
        path = pwd()

    runner = FridaRunner()
    runner.set_hook_with_data(
        ios_hook('filesystem/ls'), path=path)
    runner.run()

    # grab the output lets seeeeee
    response = runner.get_last_message()

    # ensure the response was successful
    if not response.is_successful():
        click.secho('Failed to get directory listing with error: {}'.format(response.error_reason))
        return

    # get the response data itself
    data = response.data

    # output display
    if data['readable']:

        click.secho('Read Access', fg='green')

    else:
        click.secho('No Read Access', fg='red')

    if data['writable']:

        click.secho('Write Access', fg='green')

    else:
        click.secho('No Write Access', fg='red')

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

    # if the directory was readable, dump the filesytem listing
    # and attributes to screen.
    if data['readable']:

        table_data = []
        for file_name, file_data in data['files'].items():
            # extract the attributes
            attributes = file_data['attributes']

            table_data.append([
                _get_key_if_exists(attributes, 'NSFileType'),
                _get_key_if_exists(attributes, 'NSFilePosixPermissions'),

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
                             headers=['Type', 'Perms', 'Read', 'Write', 'Owner', 'Group', 'Size', 'Creation', 'Name']))


def _ls_android(path: str) -> None:
    """
        This will be the method used to get directory listings
        on Android devices.

        :param path:
        :return:
    """

    pass


def download(args: list) -> None:
    """
        Downloads a file from a remote filesystem and stores
        it locally.

        This method is simply a proxy to the actual download methods
        used for the appopriate environment.

        :param args:
        :return:
    """

    if len(args) < 2:
        click.secho('Usage: file download <remote location> <local destination>', bold=True)
        return

    path = args[0]
    destination = args[1]

    if device_state.device_type == 'ios':
        _download_ios(path, destination)

    if device_state.device_type == 'android':
        pass


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

    if not response.is_successful():
        click.secho('Unable to download file')
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


def upload(args: list) -> None:
    """
        Uploads a local file to the remote operating system.

        This method is just a proxy method to the real upload
        method used based on the runtime that is available.

        :param args:
        :return:
    """

    if len(args) < 2:
        click.secho('Usage: file upload <local source> <remote destination>', bold=True)
        return

    path = args[0]
    destination = args[1]

    if device_state.device_type == 'ios':
        _upload_ios(path, destination)

    if device_state.device_type == 'android':
        pass


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
