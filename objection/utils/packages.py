import datetime
import lzma
import os
import plistlib
import shutil
import tempfile
import zipfile

import click
import delegator
import requests

# default paths
objection_path = os.path.join(os.path.expanduser('~'), '.objection')

android_library_path = os.path.join(objection_path, 'android')
gadget_versions = os.path.join(objection_path, 'gadget_versions')


class Github(object):
    """ Class used to interact with Github """

    GITHUB_RELEASE = 'https://api.github.com/repos/frida/frida/releases/latest'

    def __init__(self):
        """
            Init a new instance of Github
        """

        self.request_cache = {}

    def _call(self, endpoint: str) -> dict:
        """
            Make a call to Github and cache the response.

            :param endpoint:
            :return:
        """

        # return a cached response if possible
        if endpoint in self.request_cache:
            return self.request_cache[endpoint]

        # get a new response
        results = requests.get(endpoint).json()

        # cache it
        self.request_cache[endpoint] = results

        # and return it
        return results

    def get_latest_version(self) -> str:
        """
            Call Github and get the tag_name of the latest
            release.

            :return:
        """

        return self._call(self.GITHUB_RELEASE)['tag_name']

    def get_assets(self) -> dict:
        """
            Gets the assets for the latest release.

            :return:
        """

        return self._call(self.GITHUB_RELEASE)['assets']


class IosGadget(object):
    """ Class used to work with the iOS Frida Gadget """

    ios_dylib_path = os.path.join(objection_path, 'ios')
    ios_dylib_gadget_path = os.path.join(ios_dylib_path, 'FridaGadget.dylib')
    ios_dylib_gadget_archive_path = os.path.join(ios_dylib_path, 'FridaGadget.dylib.xz')

    def __init__(self, github: Github) -> None:
        """
            Instantiate a new IosGadget class, providing an already
            instantiated Github instance.

            :param github:
        """

        self.github = github

        # ensure we have the ios gadget path available
        if not os.path.exists(self.ios_dylib_path):
            os.makedirs(self.ios_dylib_path)

    @staticmethod
    def get_local_version() -> str:
        """
            Check and return the local version of the FridaGadget
            we have.

            :return:
        """

        if not os.path.exists(gadget_versions):
            return '0'

        with open(gadget_versions, 'r') as f:
            return f.read()

    def set_local_version(self, version: str):
        """
            Writes the version number to file, recording it as
            the current local version.

            :param version:
            :return:
        """

        with open(gadget_versions, 'w') as f:
            f.write(version)

        return self

    def get_gadget_path(self) -> str:
        """
            Returns the path on disk where the iOS FridaGadget
            can be found.

            :return:
        """

        return self.ios_dylib_gadget_path

    def download(self):
        """
            Downloads the latest iOS gadget.

            :return:
        """

        download_url = self._get_download_url()

        # stream the download using requests
        dylib = requests.get(download_url, stream=True)

        # save the requests stream to file
        with open(self.ios_dylib_gadget_archive_path, 'wb') as f:
            click.secho('Downloading iOS dylib to {0}...'.format(self.ios_dylib_gadget_archive_path),
                        fg='green', dim=True)

            shutil.copyfileobj(dylib.raw, f)

        return self

    def _get_download_url(self) -> str:
        """
            Determines the download URL to use for the iOS
            gadget.

            :return:
        """

        url = ''

        for asset in self.github.get_assets():
            if 'ios-universal.dylib.xz' in asset['name']:
                url = asset['browser_download_url']

        if not url:
            click.secho('Unable to determine URL to download the dylib', fg='red')
            raise Exception('Unable to determine URL for iOS gadget download.')

        return url

    def unpack(self):
        """
            Unpacks a downloaded .xz gadget.

            :return:
        """

        click.secho('Unpacking {0}...'.format(self.ios_dylib_gadget_archive_path), dim=True)

        with lzma.open(self.ios_dylib_gadget_archive_path) as f:
            with open(self.ios_dylib_gadget_path, 'wb') as g:
                g.write(f.read())

        return self

    def cleanup(self):
        """
            Cleans up a downloaded iOS .xz gadget.

            :return:
        """

        click.secho('Cleaning up downloaded archives...', dim=True)

        os.remove(self.ios_dylib_gadget_archive_path)


class IosPatcher(object):
    """ Class used to Patch iOS applications """

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

    def __init__(self):
        """
            Init a new instance of the IosPatcher class.
        """

        self.provision_file = None
        self.payload_directory = None
        self.app_folder = None
        self.app_binary = None
        self.patched_ipa_path = None
        self.patched_codesigned_ipa_path = None

        # check dependencies
        self.have_all_commands = self._check_commands()

        # temp_file to copy an IPA to
        _, self.temp_file = tempfile.mkstemp(suffix='.ipa')

        # a working directory to extract the IPA to
        self.temp_directory = os.path.dirname(self.temp_file)

        # cleanup the temp_directory to work with
        self._cleanup_extracted_data()

    def _check_commands(self) -> bool:
        """
            Check if the shell commands in required_commands are
            available.

            :return:
        """

        for cmd, attributes in self.required_commands.items():

            location = delegator.run('which {0}'.format(cmd)).out.strip()

            if len(location) <= 0:
                click.secho('Unable to find {0}. Install it with: {1} before continuing.'.format(
                    cmd, attributes['installation']), fg='red', bold=True)

                return False

            self.required_commands[cmd]['location'] = location

        return True

    def are_requirements_met(self):
        """
            Checks if the command requirements have all been met.

            :return:
        """

        return self.have_all_commands

    def set_provsioning_profile(self, provision_file: str = None) -> None:
        """
            Sets the provision file to use during patching.

            :param provision_file:
            :return:
        """

        # have provision file? set it and be done
        if provision_file:
            self.provision_file = provision_file
            return

        click.secho('No provision file specified, searching for one...', bold=True)

        # locate a valid mobile provision on disk in: ~/Library/Developer/Xcode/DerivedData/
        possible_provisions = [os.path.join(dp, f) for dp, dn, fn in
                               os.walk(os.path.expanduser('~/Library/Developer/Xcode/DerivedData/'))
                               for f in fn if 'embedded.mobileprovision' in f]

        if len(possible_provisions) <= 0:
            click.secho('No provisioning files found. Please specify one or generate one by building an app.',
                        fg='red')
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
                    self.required_commands['security']['location'],
                    pf,
                    decoded_location
                )
            )

            # read the expiration date from the profile
            with open(decoded_location, 'rb') as f:
                parsed_data = plistlib.load(f)

                if parsed_data['ExpirationDate'] > current_time:
                    expirations[pf] = parsed_data['ExpirationDate'] - current_time
                    click.secho('Found provision {0} expiring {1}'.format(pf, expirations[pf]), dim=True)

            # cleanup the temp path
            os.remove(decoded_location)

        # ensure that we got some valid mobileprovisions to work with
        if len(expirations) <= 0:
            click.secho('Could not find a non-expired provisioning file. Please specify or generate one.', fg='red')
            return

        # sort the results so that the mobileprovision with the most time is at
        # the top of the list
        click.secho('Found a valid provisioning profile', fg='green', bold=True)
        self.provision_file = sorted(expirations, key=expirations.get, reverse=True)[0]

    def extract_ipa(self, ipa_source: str) -> None:
        """
            Extracts a source IPA into the temporary directories.

            :param ipa_source:
            :return:
        """

        # copy the orignal ipa to the temp directory.
        shutil.copyfile(ipa_source, self.temp_file)

        # extract the IPA this should result in a 'Payload' directory
        ipa = zipfile.ZipFile(self.temp_file, 'r')
        ipa.extractall(self.temp_directory)
        ipa.close()

        # check what is in the Payload directory
        self.payload_directory = os.listdir(os.path.join(self.temp_directory, 'Payload'))
        if len(self.payload_directory) > 1:
            click.secho('Warning: Payload folder has more than one file, this is unexpected.', fg='yellow')

        # get the folder that ends with .app. This is where we will be patching
        # the executable with FridaGadget
        app_name = ''.join([x for x in self.payload_directory if x.endswith('.app')])
        click.secho('Working with app: {0}'.format(app_name))

        self.app_folder = os.path.join(self.temp_directory, 'Payload', app_name)

    def set_application_binary(self, binary: str = None) -> None:
        """
            Sets the binary that will be patched.

            If a binary is not defined, the applications Info.plist is parsed
            and the CFBundleIdentifier key read.

            :param binary:
            :return:
        """

        if binary is not None:
            click.secho('Using user provided binary name of: {0}'.format(binary))
            self.app_binary = os.path.join(self.app_folder, binary)

            return

        with open(os.path.join(self.app_folder, 'Info.plist'), 'rb') as f:
            info_plist = plistlib.load(f)

        # print the bundle identifier
        click.secho('Bundle identifier is: {0}'.format(info_plist['CFBundleIdentifier']),
                    fg='green', bold=True)

        self.app_binary = os.path.join(self.app_folder, info_plist['CFBundleExecutable'])

    def patch_and_codesign_binary(self, frida_gadget: str, codesign_signature: str) -> None:
        """
            Patches an iOS binary to load a Frida gadget on startup.

            Any other dylibs within the application will also be code signed with
            the same signature used for the FridaGadget itself.

            :param frida_gadget:
            :param codesign_signature:
            :return:
        """

        if not self.app_binary:
            raise Exception('The applications binary should be set first.')

        if not self.app_folder:
            raise Exception('The application should be extracted first.')

        # create a Frameworks directory if it does not already exist
        if not os.path.exists(os.path.join(self.app_folder, 'Frameworks')):
            click.secho('Creating Frameworks directory for FridaGadget...', fg='green')
            os.mkdir(os.path.join(self.app_folder, 'Frameworks'))

        # copy the frida gadget to the applications Frameworks directory
        shutil.copyfile(frida_gadget, os.path.join(self.app_folder, 'Frameworks', 'FridaGadget.dylib'))

        # patch the app binary
        load_library_output = delegator.run(
            '{0} {1} {2} {3} "{4}"'.format(
                self.required_commands['insert_dylib']['location'],
                '--strip-codesig',
                '--inplace',
                '@executable_path/Frameworks/FridaGadget.dylib',
                self.app_binary)
        )

        # check if the insert_dylib call may have failed
        if 'Added LC_LOAD_DYLIB' not in load_library_output.out:
            click.secho('Injecting the load library to {0} might have failed.'.format(self.app_binary),
                        fg='yellow')
            click.secho(load_library_output.out, fg='red', dim=True)
            click.secho(load_library_output.err, fg='red')

        # get the paths of all of the .dylib files in this applications
        # bundle. we will have to codesign all of them and not just the
        # frida gadget
        dylibs_to_sign = [
            os.path.join(dp, f) for dp, dn, fn in os.walk(self.app_folder) for f in fn if f.endswith('.dylib')]

        # codesign the dylibs in this bundle
        click.secho('Codesigning {0} .dylib\'s with signature {1}'.format(len(dylibs_to_sign), codesign_signature),
                    fg='green')
        for dylib in dylibs_to_sign:
            click.secho('Code signing: {0}'.format(os.path.basename(dylib)), dim=True)
            delegator.run('{0} {1} {2} {3}'.format(self.required_commands['codesign']['location'],
                                                   '-f -v -s',
                                                   codesign_signature,
                                                   dylib))

    def archive_and_codesign(self, original_name: str, codesign_signature: str) -> None:
        """
            Creates a new archive of the patched IPA.

            :param original_name:
            :param codesign_signature:
            :return:
        """

        click.secho('Creating new archive with patched contents.', dim=True)
        self.patched_ipa_path = os.path.join(self.temp_directory,
                                             os.path.basename('{0}-frida.ipa'.format(original_name.strip('.ipa'))))

        def zipdir(path, ziph):
            # ziph is a zipfile handle
            for root, dirs, files in os.walk(path):
                for fi in files:
                    ziph.write(os.path.join(root, fi),
                               os.path.relpath(os.path.join(root, fi), os.path.join(path, '..')))

        zipf = zipfile.ZipFile(self.patched_ipa_path, 'w')
        zipdir(os.path.join(self.temp_directory, 'Payload'), zipf)
        zipf.close()

        # codesign the new ipa
        click.secho('Codesigning patched IPA...', fg='green')
        self.patched_codesigned_ipa_path = os.path.join(self.temp_directory, os.path.basename(
            '{0}-frida-codesigned.ipa'.format(original_name.strip('.ipa'))))

        ipa_codesign = delegator.run(
            '{0} -i {1} -m "{2}" -o "{3}" "{4}"'.format(
                self.required_commands['applesign']['location'],
                codesign_signature,
                self.provision_file,
                self.patched_codesigned_ipa_path,
                self.patched_ipa_path,
            )
        )

        click.secho(ipa_codesign.err, dim=True)

    def get_patched_ipa_path(self) -> str:
        """
            Returns the path where the final patched IPA would be.

            :return:
        """

        return self.patched_codesigned_ipa_path

    def _cleanup_extracted_data(self) -> None:
        """
            Small helper method to cleanup temporary files created
            when an older IPA was extracted.

            :return:
        """

        p = os.path.join(self.temp_directory, 'Payload')
        shutil.rmtree(p, ignore_errors=True)

    def __del__(self):
        """
            Cleanup after ourselves.

            :return:
        """

        click.secho('Cleaning up temp files...', dim=True)

        try:

            self._cleanup_extracted_data()
            os.remove(self.temp_file)
            os.remove(self.patched_ipa_path)
            os.remove(self.patched_codesigned_ipa_path)

        except Exception as err:
            click.secho('Failed to cleanup with error: {0}'.format(err), fg='red')
