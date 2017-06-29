import datetime
import os
import shutil
import tempfile
import zipfile

import click
import delegator
import requests


def _get_frida_gadget(platform):
    objection_path = os.path.join(os.path.expanduser('~'), '.objection')

    # Ensure we have the objection path
    if not os.path.exists(objection_path):
        os.makedirs(objection_path)

    if platform == 'ios':
        update_now = True

        dylib_path = os.path.join(objection_path, 'FridaGadget.dylib')

        if os.path.exists(dylib_path):

            # check if the dylib was downloaded more than 3 days ago
            created = os.path.getctime(dylib_path)
            if datetime.datetime.fromtimestamp(created) > datetime.datetime.now() - datetime.timedelta(days=3):
                update_now = False

        if update_now:
            frida_gadget_url = 'https://build.frida.re/frida/ios/lib/FridaGadget.dylib'
            click.secho('Updating to newest FridaGadget from: {0}...'.format(frida_gadget_url))

            frida_gadget = requests.get(frida_gadget_url, stream=True)
            with open(dylib_path, 'wb') as f:
                click.secho('Streaming dylib to ~/.objection cache...', fg='green', dim=True)
                shutil.copyfileobj(frida_gadget.raw, f)

        return dylib_path

    if platform == 'android':
        raise Exception('Non yet implemented')


def patch_ios_ipa(source, codesign_signature, provision_file, binary_name):
    def cleanup_extracted_payload(t):

        p = os.path.join(t, 'Payload')
        shutil.rmtree(p, ignore_errors=True)
        return

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
    if binary_name is None:
        app_binary = os.path.join(app_folder, os.path.splitext(os.path.basename(app_folder))[0])
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

    # codesign the FridaGadget
    click.secho('Codesigning FridaGadget.dylib with signature {0}'.format(codesign_signature))
    delegator.run('{0} {1} {2} {3}'.format(required_commands['codesign']['location'],
                                           '-f -v -s',
                                           codesign_signature,
                                           os.path.join(app_folder, 'Frameworks', 'FridaGadget.dylib')))

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
