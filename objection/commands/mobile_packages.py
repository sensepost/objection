import datetime
import os
import plistlib
import shutil
import tempfile
import zipfile

import click
import delegator
import requests


def _get_frida_gadget(platform: str) -> str:
    """
        Gets the location of the Frida Gadget on disk.

        If the applicable library is not on disk in the ~/.objection
        directory, or, if its older than 3 days, a new version will be
        downloaded.

        :param platform:
        :return:
    """

    objection_path = os.path.join(os.path.expanduser('~'), '.objection')

    # Ensure we have the objection path
    if not os.path.exists(objection_path):
        os.makedirs(objection_path)

    # handle the ios specific gadget
    if platform == 'ios':

        # by default, assume the gadget needs downloading
        update_now = True
        dylib_path = os.path.join(objection_path, 'FridaGadget.dylib')

        if os.path.exists(dylib_path):

            # check if the dylib was downloaded less than 3 days ago
            created = os.path.getctime(dylib_path)
            if datetime.datetime.fromtimestamp(created) > datetime.datetime.now() - datetime.timedelta(days=3):
                update_now = False

        # if needed, download the latest versio of the dylib
        if update_now:
            frida_gadget_url = 'https://build.frida.re/frida/ios/lib/FridaGadget.dylib'
            click.secho('Updating to newest FridaGadget from: {0}...'.format(frida_gadget_url))

            # Save the gadget to file
            frida_gadget = requests.get(frida_gadget_url, stream=True)
            with open(dylib_path, 'wb') as f:
                click.secho('Streaming dylib to ~/.objection cache...', fg='green', dim=True)
                shutil.copyfileobj(frida_gadget.raw, f)

        return dylib_path

    if platform == 'android':
        raise Exception('Non yet implemented')


def patch_ios_ipa(source: str, codesign_signature: str, provision_file: str, binary_name: str) -> None:
    """
        Patches an iOS IPA by extracting, injecting the Frida dylib,
        codesigning the dylib and app executable and rezipping the IPA.

        :param source:
        :param codesign_signature:
        :param provision_file:
        :param binary_name:
        :return:
    """

    def cleanup_extracted_payload(t: str) -> None:
        """
            Small helper method to cleanup temporary files created
            when an IPA is extracted.

            :param t:
            :return:
        """

        p = os.path.join(t, 'Payload')
        shutil.rmtree(p, ignore_errors=True)

    # dictionary of commands and installation methods required for
    # the patching process to work.
    required_commands = {
        'xcodebuild': {
            'installation': 'Install XCode on macOS via the Appstore'
        },
        'applesign': {
            'installation': 'npm install -g node-applesign'
        },
        'insert_dylib': {
            'installation': ('git clone https://github.com/Tyilo/insert_dylib && cd insert_dylib &&'
                             'xcodebuild && cp build/Release/insert_dylib /usr/local/bin/insert_dylib')
        },
        'codesign': {
            'installation': 'Part of XCode'
        },
        'security': {
            'installation': 'macOS builtin command'
        },
        'zip': {
            'installation': 'macOS builtin command'
        },
        'unzip': {
            'installation': 'macOS builtin command'
        }
    }

    # check that we have all of the commands needed to build the patched ipa
    for cmd, attributes in required_commands.items():
        location = delegator.run('which {0}'.format(cmd)).out.strip()

        if len(location) <= 0:
            click.secho('Unable to find {0}. Install it with: {1}'.format(cmd, attributes['installation']))
            return

        required_commands[cmd]['location'] = location

    _, temp_file = tempfile.mkstemp(suffix='.ipa')

    # check if we have a mobile provision to work with, else we search for one
    if not provision_file:
        click.secho('No provision file specified, searching for one...')
        possible_provisions = [
            os.path.join(dp, f) for dp, dn, fn in os.walk(os.path.expanduser('~/Library/Developer/Xcode/DerivedData/'))
            for f in fn if 'embedded.mobileprovision' in f]

        if len(possible_provisions) <= 0:
            click.secho('No provisioning files found. Please specify one or generate one by building an app.', fg='red')
            return

        # we have some provisioning profiles, lets find the one
        # with the most days left
        current_time = datetime.datetime.now()
        expirations = {}

        for pf in possible_provisions:
            _, decoded_location = tempfile.mkstemp('decoded_provision')

            # Decode the mobile provision using macOS's security cms tool
            delegator.run(
                '{0} cms -D -i {1} > {2}'.format(
                    required_commands['security']['location'],
                    pf,
                    decoded_location
                )
            )

            with open(decoded_location, 'rb') as f:
                parsed_data = plistlib.load(f)
                # print(l['CreationDate'], l['ExpirationDate'])

                if parsed_data['ExpirationDate'] > current_time:
                    expirations[pf] = parsed_data['ExpirationDate'] - current_time

            os.remove(decoded_location)

        # ensure that we got some valid mobileprovisions to work with
        if len(expirations) <= 0:
            click.secho('Could not find a non-expired provisioning file. Please specify or generate one.', fg='red')
            return

        # sort the results so that the mobileprovision with the most time is at
        # the top of the list
        click.secho('Found a valid provisioning file', fg='green')
        provision_file = sorted(expirations, key=expirations.get, reverse=True)[0]

    # get a place to work with the IPA
    temp_directory = os.path.dirname(temp_file)

    # ensure there is no Payload directory before we extract
    cleanup_extracted_payload(temp_directory)

    # copy the ipa to the temp directory.
    shutil.copyfile(source, temp_file)

    # extract the IPA this should result in a 'Payload' directory
    ipa = zipfile.ZipFile(temp_file, 'r')
    ipa.extractall(temp_directory)
    ipa.close()

    # check what is in the payloads directory
    payload_directory = os.listdir(os.path.join(temp_directory, 'Payload'))
    if len(payload_directory) > 1:
        click.secho('Warning: Payload folder has more than one file, this is unexpected.', fg='yellow')

    # get the folder that ends with .app. This is where we will be patching
    # the executable with FridaGadget
    app_name = ''.join([x for x in payload_directory if x.endswith('.app')])
    click.secho('Working with app: {0}'.format(app_name))

    app_folder = os.path.join(temp_directory, 'Payload', app_name)

    # determine the name of the binary from the Info.plist
    if binary_name is None:

        with open(os.path.join(app_folder, 'Info.plist'), 'rb') as f:
            info_plist = plistlib.load(f)

        # print the bundle identifier
        click.secho('Bundle identifier is: {0}'.format(info_plist['CFBundleIdentifier']), fg='green', bold=True)

        app_binary = os.path.join(app_folder, info_plist['CFBundleExecutable'])
    else:
        app_binary = os.path.join(app_folder, binary_name)

    if not os.path.exists(os.path.join(app_folder, 'Frameworks')):
        click.secho('Creating Frameworks directory for FridaGadget...', fg='green')
        os.mkdir(os.path.join(app_folder, 'Frameworks'))

    # copy the frida gadget
    frida_gadget = _get_frida_gadget('ios')
    shutil.copyfile(frida_gadget, os.path.join(app_folder, 'Frameworks', 'FridaGadget.dylib'))

    # patch the app binary
    load_library_output = delegator.run(
        '{0} {1} {2} {3} "{4}"'.format(
            required_commands['insert_dylib']['location'],
            '--strip-codesig',
            '--inplace',
            '@executable_path/Frameworks/FridaGadget.dylib',
            app_binary)
    )

    if 'Added LC_LOAD_DYLIB' not in load_library_output.out:
        click.secho('Injecting the load library to {0} might have failed.'.format(app_binary), fg='yellow')
        click.secho(load_library_output.out, fg='red', dim=True)
        click.secho(load_library_output.err, fg='red')

    # get the paths of all of the .dylib files in this applications
    # bundle. we will have to codesign all of them and not just the
    # frida gadget
    dylibs_to_sign = [os.path.join(dp, f) for dp, dn, fn in os.walk(app_folder) for f in fn if f.endswith('.dylib')]

    # codesign the dylibs in this bundle
    click.secho('Codesigning {0} .dylib\'s with signature {1}'.format(len(dylibs_to_sign), codesign_signature),
                fg='green')
    for dylib in dylibs_to_sign:
        click.secho('Code signing: {0}'.format(os.path.basename(dylib)), dim=True)
        delegator.run('{0} {1} {2} {3}'.format(required_commands['codesign']['location'],
                                               '-f -v -s',
                                               codesign_signature,
                                               dylib))

    # zip up the new ipa
    click.secho('Preparing IPA for codesigning...')
    patched_ipa_path = os.path.join(temp_directory, os.path.basename('{0}-frida.ipa'.format(source.strip('.ipa'))))

    def zipdir(path, ziph):
        # ziph is zipfile handle
        for root, dirs, files in os.walk(path):
            for fi in files:
                ziph.write(os.path.join(root, fi), os.path.relpath(os.path.join(root, fi), os.path.join(path, '..')))

    zipf = zipfile.ZipFile(patched_ipa_path, 'w')
    zipdir(os.path.join(temp_directory, 'Payload'), zipf)
    zipf.close()

    # cleanup the Payload directory
    cleanup_extracted_payload(temp_directory)

    # codesign the new ipa
    click.secho('Codesigning patched IPA...', fg='green')
    patched_codesigned_ipa_path = os.path.join(temp_directory, os.path.basename(
        '{0}-frida-codesigned.ipa'.format(source.strip('.ipa'))))
    ipa_codesign = delegator.run(
        '{0} -i {1} -m "{2}" -o "{3}" "{4}"'.format(
            required_commands['applesign']['location'],
            codesign_signature,
            provision_file,
            patched_codesigned_ipa_path,
            patched_ipa_path,
        )
    )
    click.secho(ipa_codesign.err, dim=True)

    # copy codesigned app to local dir
    click.secho('Copying final ipa from {0} to current directory...'.format(patched_codesigned_ipa_path))
    shutil.copyfile(
        patched_codesigned_ipa_path,
        os.path.join(os.path.abspath('.'), os.path.basename(patched_codesigned_ipa_path))
    )

    # cleanups
    click.secho('Cleaning up temp files')
    cleanup_extracted_payload(temp_directory)
    os.remove(temp_file)
    os.remove(patched_ipa_path)
    os.remove(patched_codesigned_ipa_path)
