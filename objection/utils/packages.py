import datetime
import json
import lzma
import os
import plistlib
import shutil
import tempfile
import xml.etree.ElementTree as ElementTree
import zipfile
from subprocess import list2cmdline

import click
import delegator
import requests

# default paths
objection_path = os.path.join(os.path.expanduser('~'), '.objection')
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


class BasePlatformGadget(object):
    """ Class with base methods for any platforms Gadget downloaded """

    def __init__(self, github: Github) -> None:
        """
            Build a new instance with an existing Github instance.

            :param github:
        """

        self.github = github

    @staticmethod
    def get_local_version(gadget_type: str) -> str:
        """
            Check and return the local version of the FridaGadget
            type we have.

            :return:
        """

        if not os.path.exists(gadget_versions):
            return '0'

        with open(gadget_versions, 'r') as f:
            versions = f.read()

        # load the json.
        try:

            versions = json.loads(versions)

        except json.decoder.JSONDecodeError:
            return '0'

        if gadget_type in versions:
            return versions[gadget_type]

        return '0'

    def set_local_version(self, gadget_type: str, version: str):
        """
            Writes the version number to file, recording it as
            the current local version.

            :param gadget_type:
            :param version:
            :return:
        """

        # read the current versions if it exists, else start
        # a new dictionary for it
        if os.path.exists(gadget_versions):

            # load the json from disk
            try:

                with open(gadget_versions, 'r') as f:
                    versions = json.loads(f.read())

            except json.decoder.JSONDecodeError:
                versions = {}

        else:
            versions = {}

        # add the new version
        versions[gadget_type] = version

        # and write it to file
        with open(gadget_versions, 'w') as f:
            f.write(json.dumps(versions))

        return self


class BasePlatformPatcher(object):
    """ Base class with methods used by any platform patcher. """

    # extended classes should fill this property
    required_commands = {}

    def __init__(self):

        # check dependencies
        self.have_all_commands = self._check_commands()
        self.command_run_timeout = 60 * 5

    def _check_commands(self) -> bool:
        """
            Check if the shell commands in required_commands are
            available.

            :return:
        """

        for cmd, attributes in self.required_commands.items():

            location = shutil.which(cmd)

            if location is None:
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


class IosGadget(BasePlatformGadget):
    """ Class used to work with the iOS Frida Gadget """

    ios_dylib_path = os.path.join(objection_path, 'ios')
    ios_dylib_gadget_path = os.path.join(ios_dylib_path, 'FridaGadget.dylib')
    ios_dylib_gadget_archive_path = os.path.join(ios_dylib_path, 'FridaGadget.dylib.xz')

    def __init__(self, github: Github) -> None:
        """
            Build a new instance, ensuring that the paths needed
            are available.

            :param github:
        """

        super(IosGadget, self).__init__(github)

        # ensure we have the ios gadget path available
        if not os.path.exists(self.ios_dylib_path):
            os.makedirs(self.ios_dylib_path)

    def get_gadget_path(self) -> str:
        """
            Returns the path on disk where the iOS FridaGadget
            can be found.

            :return:
        """

        return self.ios_dylib_gadget_path

    def gadget_exists(self):
        """
            Checks if the iOS gadget exists on disk.

            :return:
        """

        return os.path.exists(self.ios_dylib_gadget_path)

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


class IosPatcher(BasePlatformPatcher):
    """ Class used to Patch iOS applications """

    required_commands = {
        'xcodebuild': {
            'installation': 'Install XCode on macOS via the Appstore'
        },
        'applesign': {
            'installation': 'npm install -g applesign'
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

        super(IosPatcher, self).__init__()

        self.provision_file = None
        self.payload_directory = None
        self.app_folder = None
        self.app_binary = None
        self.patched_ipa_path = None
        self.patched_codesigned_ipa_path = None

        # temp_file to copy an IPA to
        _, self.temp_file = tempfile.mkstemp(suffix='.ipa')

        # a working directory to extract the IPA to
        self.temp_directory = os.path.dirname(self.temp_file)

        # cleanup the temp_directory to work with
        self._cleanup_extracted_data()

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
            delegator.run(list2cmdline(
                [
                    self.required_commands['security']['location'],
                    'cms',
                    '-D',
                    '-i',
                    pf,
                    '-o',
                    decoded_location
                ]
            ), timeout=self.command_run_timeout)

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
        load_library_output = delegator.run(list2cmdline(
            [
                self.required_commands['insert_dylib']['location'],
                '--strip-codesig',
                '--inplace',
                '@executable_path/Frameworks/FridaGadget.dylib',
                self.app_binary
            ]
        ), timeout=self.command_run_timeout)

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
            delegator.run(list2cmdline([
                self.required_commands['codesign']['location'],
                '-f',
                '-v',
                '-s',
                codesign_signature,
                dylib])
            )

    def archive_and_codesign(self, original_name: str, codesign_signature: str) -> None:
        """
            Creates a new archive of the patched IPA.

            :param original_name:
            :param codesign_signature:
            :return:
        """

        click.secho('Creating new archive with patched contents...', dim=True)
        self.patched_ipa_path = os.path.join(
            self.temp_directory, os.path.basename(
                '{0}-frida.ipa'.format(os.path.splitext(original_name)[0])))

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
            '{0}-frida-codesigned.ipa'.format(os.path.splitext(original_name)[0])))

        ipa_codesign = delegator.run(list2cmdline(
            [
                self.required_commands['applesign']['location'],
                '-i',
                codesign_signature,
                '-m',
                self.provision_file,
                '-o',
                self.patched_codesigned_ipa_path,
                self.patched_ipa_path
            ]
        ), timeout=self.command_run_timeout)

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


class AndroidGadget(BasePlatformGadget):
    """ Class used to download Android Frida libraries """

    android_library_path = os.path.join(objection_path, 'android')

    # Lists the supported architectures. Key matches Android support
    # https://developer.android.com/ndk/guides/abis.html#sa
    # Value matches library arch for frida.
    architectures = {
        'armeabi': 'arm',
        'armeabi-v7a': 'arm',
        'arm64': 'arm64',
        'arm64-v8a': 'arm64',
        'x86': 'x86',
        'x86_64': 'x86_64',
    }

    def __init__(self, github: Github) -> None:
        """
            Build a new instance, ensuring that the paths needed
            are available.

            :param github:
        """

        super(AndroidGadget, self).__init__(github)

        self.architecture = None

        # prep paths. if they dont exist, create them
        for path in self.architectures.keys():

            d = os.path.join(self.android_library_path, path)

            if not os.path.exists(d):
                os.makedirs(d)

    def set_architecture(self, architecture: str):
        """
            Set the CPU architecture we will work with.

            :param architecture:
            :return:
        """

        if architecture not in self.architectures.keys():
            raise Exception('Invalid architecture `{0}` set. Valid options are: {1}'.format(
                architecture, ', '.join(self.architectures)))

        self.architecture = architecture

        return self

    def get_architecture(self) -> str:
        """
            Get the architecture we are working with.

            :return:
        """

        return self.architecture

    def get_frida_library_path(self, packed: bool = False) -> str:
        """
            Get the path to a frida-library, both in the packed and

            :param packed:
            :return:
        """

        if not self.architecture:
            raise Exception('Unable to determine path without architecture')

        return os.path.join(self.android_library_path, self.architecture,
                            'libfrida-gadget.so' + ('.xz' if packed else ''))

    def gadget_exists(self) -> bool:
        """
            Determines of a frida-gadget library exists.

            :return:
        """

        if not self.architecture:
            raise Exception('Unable to determine path without architecture')

        return os.path.exists(self.get_frida_library_path())

    def download(self):
        """
            Downloads the latest Android gadget for this
            architecture.

            :return:
        """

        download_url = self._get_download_url()

        # stream the download using requests
        library = requests.get(download_url, stream=True)
        library_destination = self.get_frida_library_path(packed=True)

        # save the requests stream to file
        with open(library_destination, 'wb') as f:
            click.secho('Downloading {0} library to {1}...'.format(self.architecture,
                                                                   library_destination), fg='green', dim=True)

            shutil.copyfileobj(library.raw, f)

        return self

    def _get_download_url(self) -> str:
        """
            Determines the download URL to use for the iOS
            gadget.

            :return:
        """

        url = ''

        # url should contain 'frida-gadget-{version}-android-{arch}.so.xz
        url_start = 'frida-gadget-'
        url_end = 'android-' + self.architectures[self.architecture] + '.so.xz'

        for asset in self.github.get_assets():
            if asset['name'].startswith(url_start) and asset['name'].endswith(url_end):
                url = asset['browser_download_url']

        if not url:
            click.secho('Unable to determine URL to download the library', fg='red')
            raise Exception('Unable to determine URL for iOS gadget download.')

        return url

    def unpack(self):
        """
            Unpacks a downloaded .xz gadget.

            :return:
        """

        click.secho('Unpacking {0}...'.format(self.get_frida_library_path(packed=True)), dim=True)

        with lzma.open(self.get_frida_library_path(packed=True)) as f:
            with open(self.get_frida_library_path(), 'wb') as g:
                g.write(f.read())

        return self

    def cleanup(self):
        """
            Cleans up a downloaded iOS .xz gadget.

            :return:
        """

        click.secho('Cleaning up downloaded archives...', dim=True)

        os.remove(self.get_frida_library_path(packed=True))


class AndroidPatcher(BasePlatformPatcher):
    """ Class used to patch Android APK's"""

    required_commands = {
        'aapt': {
            'installation': 'apt install appt (Kali Linux)'
        },
        'adb': {
            'installation': 'apt install adb (Kali Linux); brew install adb (macOS)'
        },
        'jarsigner': {
            'installation': '#TODO'
        },
        'apktool': {
            'installation': 'apt install apktool (Kali Linux)'
        }
    }

    def __init__(self):
        super(AndroidPatcher, self).__init__()

        self.apk_source = None
        self.apk_temp_directory = tempfile.mkdtemp(suffix='.apktemp')
        self.apk_temp_frida_patched = self.apk_temp_directory + '.objection.apk'
        self.aapt = None

    def set_apk_source(self, source: str):
        """
            Set the source APK to work with.

            :param source:
            :return:
        """

        if not os.path.exists(source):
            raise Exception('Source {0} not found.'.format(source))

        self.apk_source = source

        return self

    def _get_android_manifest(self) -> ElementTree:
        """
            Get the AndroidManifest as a parsed ElementTree

            :return:
        """

        # use the android namespace
        ElementTree.register_namespace('android', 'http://schemas.android.com/apk/res/android')

        return ElementTree.parse(os.path.join(self.apk_temp_directory, 'AndroidManifest.xml'))

    def _get_appt_output(self):
        """
            Get the output of `aapt dump badging`.

            :return:
        """

        if not self.aapt:
            o = delegator.run(list2cmdline(
                [
                    self.required_commands['aapt']['location'],
                    'dump',
                    'badging',
                    self.apk_source
                ]
            ), timeout=self.command_run_timeout)

            if len(o.err) > 0:
                click.secho('An error may have occured while running aapt.', fg='red')
                click.secho(o.err, fg='red')

            self.aapt = o.out

        return self.aapt

    def _get_launchable_activity(self) -> str:
        """
            Determines the class name for the activity that is
            launched on application startup.

            This is done by first trying to parse the output of
            aapt dump badging, then falling back to manually
            parsing the AndroidManifest for activity-alias tags.

            :return:
        """

        activity = ''
        aapt = self._get_appt_output().split('\n')

        for line in aapt:
            if 'launchable-activity' in line:
                # ['launchable-activity: name=', 'com.app.activity', '  label=', 'bob']
                activity = line.split('\'')[1]

        # If we got the activity using aapt, great, return that.
        if activity != '':
            return activity

        # if we dont have the activity yet, check out activity aliases

        click.secho(('Unable to determine the launchable activity using aapt, trying '
                     'to manually parse the AndroidManifest for activity aliases...'), dim=True, fg='yellow')

        # Try and parse the manifest manually
        manifest = self._get_android_manifest()
        root = manifest.getroot()

        # grab all of the activity-alias tags
        for alias in root.findall('./application/activity-alias'):

            # Take not of the current activity
            current_activity = alias.get('{http://schemas.android.com/apk/res/android}targetActivity')
            categories = alias.findall('./intent-filter/category')

            # make sure we have categories for this alias
            if categories is None:
                continue

            for category in categories:

                # check if the name of this category is that of LAUNCHER
                # its possible to have multiples, but once we determine one
                # that fits we can just return and move on
                category_name = category.get('{http://schemas.android.com/apk/res/android}name')

                if category_name == 'android.intent.category.LAUNCHER':
                    return current_activity

        # getting here means we were unable to determine what the launchable
        # activity is
        click.secho('Unable to determine the launchable activity for this app.', fg='red')
        raise Exception('Unable to determine launchable activity')

    def get_patched_apk_path(self) -> str:
        """
            Returns the path of the patched APK.

            :return:
        """

        return self.apk_temp_frida_patched

    def unpack_apk(self):
        """
            Unpack an APK with apktool.

            :return:
        """

        click.secho('Unpacking {0}'.format(self.apk_source), dim=True)

        o = delegator.run(list2cmdline(
            [
                self.required_commands['apktool']['location'],
                'decode',
                '-f',
                '-o',
                self.apk_temp_directory,
                self.apk_source
            ]
        ), timeout=self.command_run_timeout)

        if len(o.err) > 0:
            click.secho('An error may have occured while extracting the APK.', fg='red')
            click.secho(o.err, fg='red')

    def inject_internet_permission(self):
        """
            Checks the status of the source APK to see if it
            has the INTERNET permission. If not, the manifest file
            is parsed and the permission injected.

            :return:
        """

        internet_permission = 'android.permission.INTERNET'

        # if the app already has the internet permission, easymode :D
        if internet_permission in self._get_appt_output():
            click.secho('App already has android.permission.INTERNET', fg='green')
            return

        # if not, we need to inject an element with it
        xml = self._get_android_manifest()
        root = xml.getroot()

        click.secho('Injecting permission: {0}'.format(internet_permission), fg='green')

        # prepare a new 'uses-permission' tag
        child = ElementTree.Element('uses-permission')
        child.set('android:name', internet_permission)
        root.append(child)

        click.secho('Writing new Android manifest...', dim=True)

        xml.write(os.path.join(self.apk_temp_directory, 'AndroidManifest.xml'),
                  encoding='utf-8', xml_declaration=True)

    def inject_load_library(self):
        """
            Injects a loadLibrary call into the launchable
            activity of a target APK.

            Most of the idea for this comes from:
                https://koz.io/using-frida-on-android-without-root/

            :return:
        """

        # raw smali to inject.
        # ref: https://koz.io/using-frida-on-android-without-root/
        load_library = ('.method static constructor <clinit>()V\n'
                        '   .locals 1\n'
                        '\n'
                        '   .prologue\n'
                        '   const-string v0, "frida-gadget"\n'
                        '\n'
                        '   invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n'
                        '\n'
                        '   return-void\n'
                        '.end method\n')

        # the path to the smali we should inject the load_library call
        # into. we get a class name from the internal method of this
        # class, so replace .'s to /'s to get the path apktool would
        # have left it on disk.
        activity = self._get_launchable_activity().replace('.', '/')
        activity_path = os.path.join(self.apk_temp_directory, 'smali', activity) + '.smali'

        # check if the activity path exists. If not, try and see if this may have been
        # a multidex setup
        if not os.path.exists(activity_path):

            click.secho('Smali not found in smali directory. This might be a multidex APK. Searching...', dim=True)

            # apk tool will dump the dex classes to a smali directory. in multidex setups
            # we have folders such as smali_classes2, smali_classes3 etc. we will search
            # those paths for the launch activity we detected.
            for x in range(2, 100):
                smali_path = os.path.join(self.apk_temp_directory, 'smali_classes{0}'.format(x))

                # stop if the smali_classes directory does not exist.
                if not os.path.exists(smali_path):
                    break

                # determine the path to the launchable activity again
                activity_path = os.path.join(smali_path, activity) + '.smali'

                # if we found the activity, stop the loop
                if os.path.exists(activity_path):
                    click.secho('Found smali at: {0}'.format(activity_path), dim=True)
                    break

        # one final check to ensure we have the target .smali file
        if not os.path.exists(activity_path):
            raise Exception('Unable to find smali to patch!')

        click.secho('Reading smali from: {0}'.format(activity_path), dim=True)

        # apktool d smali will have a commentline line: '# direct methods'
        with open(activity_path, 'r') as f:
            smali_lines = f.readlines()

        # search for the line starting with '# direct methods' in it
        inject_marker = [i for i, x in enumerate(smali_lines) if '# direct methods' in x]

        # TODO: check if <clinit> doesnt already exist

        # ensure we got a marker
        if len(inject_marker) <= 0:
            raise Exception('Unable to determine position to inject a loadLibrary call')

        # pick the first position for the inject. add one line as we
        # want to inject right be low the comment we matched
        inject_marker = inject_marker[0] + 1

        click.secho('Injecting loadLibrary call at line: {0}'.format(inject_marker), dim=True, fg='green')

        # inject the load_library code between
        patched_smali = \
            smali_lines[:inject_marker] + load_library.splitlines(keepends=True) + smali_lines[inject_marker:]

        click.secho('Writing patched smali back to: {0}'.format(activity_path), dim=True)

        with open(activity_path, 'w') as f:
            f.write(''.join(patched_smali))

    def add_gadget_to_apk(self, architecture: str, gadget_source: str):
        """
            Copies a frida gadget for a specific architecture to
            an extracted APK's lib path.

            :param architecture:
            :param gadget_source:
            :return:
        """

        libs_path = os.path.join(self.apk_temp_directory, 'lib', architecture)

        # check if the libs path exists
        if not os.path.exists(libs_path):
            click.secho('Creating library path: {0}'.format(libs_path), dim=True)
            os.makedirs(libs_path)

        click.secho('Copying Frida gadget to libs path...', fg='green', dim=True)
        shutil.copyfile(gadget_source, os.path.join(libs_path, 'libfrida-gadget.so'))

    def build_new_apk(self):
        """
            Build a new .apk with the frida-gadget patched in.

            :return:
        """

        click.secho('Rebuilding the APK with the frida-gadget loaded...', fg='green', dim=True)
        o = delegator.run(list2cmdline(
            [
                self.required_commands['apktool']['location'],
                'build',
                self.apk_temp_directory,
                '-o',
                self.apk_temp_frida_patched
            ]
        ), timeout=self.command_run_timeout)

        if len(o.err) > 0:
            click.secho(('Rebuilding the APK may have failed. Read the following '
                         'output to determine if apktool actually had an error: \n'), fg='red')
            click.secho(o.err, fg='red')

        click.secho('Built new APK with injected loadLibrary and frida-gadget', fg='green')

    def sign_apk(self):
        """
            Signs an APK with the objection key.

            The keystore itself was created with:
                keytool -genkey -v -keystore objection.jks -alias objection -keyalg RSA -keysize 2048 -validity 3650
                pass: basil-joule-bug
        :return:
        """

        click.secho('Signing new APK.', dim=True)

        here = os.path.abspath(os.path.dirname(__file__))
        keystore = os.path.join(here, 'assets', 'objection.jks')

        o = delegator.run(list2cmdline([
            self.required_commands['jarsigner']['location'],
            '-sigalg',
            'SHA1withRSA',
            '-digestalg',
            'SHA1',
            '-storepass',
            'basil-joule-bug',
            '-keystore',
            keystore,
            self.apk_temp_frida_patched,
            'objection'])
        )

        if len(o.err) > 0:
            click.secho('Signing the new APK may have failed.', fg='red')
            click.secho(o.err, fg='red')

        click.secho('Signed the new APK', fg='green')

    def __del__(self):
        """
            Cleanup after ourselves.

            :return:
        """

        click.secho('Cleaning up temp files...', dim=True)

        try:

            shutil.rmtree(self.apk_temp_directory, ignore_errors=True)
            os.remove(self.apk_temp_frida_patched)

        except Exception as err:
            click.secho('Failed to cleanup with error: {0}'.format(err), fg='red')
