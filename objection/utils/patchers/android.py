import lzma
import os
import shutil
import tempfile
import xml.etree.ElementTree as ElementTree
from subprocess import list2cmdline

import click
import delegator
import requests

from .base import BasePlatformGadget, BasePlatformPatcher, objection_path
from .github import Github


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
        click.secho('Downloading from: {0}'.format(download_url), dim=True)

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
            Determines the download URL to use for the Android
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
            raise Exception('Unable to determine URL for Android gadget download.')

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
            'installation': 'apt install aapt (Kali Linux)'
        },
        'adb': {
            'installation': 'apt install adb (Kali Linux); brew install adb (macOS)'
        },
        'jarsigner': {
            'installation': '#TODO'
        },
        'apktool': {
            'installation': 'apt install apktool (Kali Linux)'
        },
        'zipalign': {
            'installation': 'apt install zipalign'
        }
    }

    def __init__(self, skip_cleanup: bool = False):
        super(AndroidPatcher, self).__init__()

        self.apk_source = None
        self.apk_temp_directory = tempfile.mkdtemp(suffix='.apktemp')
        self.apk_temp_frida_patched = self.apk_temp_directory + '.objection.apk'
        self.apk_temp_frida_patched_aligned = self.apk_temp_directory + '.aligned.objection.apk'
        self.aapt = None
        self.skip_cleanup = skip_cleanup

        self.keystore = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                                     '../assets', 'objection.jks')

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
            o = delegator.run(list2cmdline([
                self.required_commands['aapt']['location'],
                'dump',
                'badging',
                self.apk_source
            ]), timeout=self.command_run_timeout)

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
            Returns the path of the patched, aligned APK.

            :return:
        """

        return self.apk_temp_frida_patched_aligned

    def get_temp_working_directory(self) -> str:
        """
            Returns the temporary working directory used by this patcher.

            :return:
        """

        return self.apk_temp_directory

    def unpack_apk(self, decode_resources: bool = False):
        """
            Unpack an APK with apktool.

            :type decode_resources: bool

            :return:
        """

        click.secho('Unpacking {0}'.format(self.apk_source), dim=True)

        o = delegator.run(list2cmdline([
            self.required_commands['apktool']['location'],
            'decode',
            '-f',
            '-r' if not decode_resources else '',
            '-o',
            self.apk_temp_directory,
            self.apk_source
        ]), timeout=self.command_run_timeout)

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

    def flip_debug_flag_to_true(self):
        """
            Set the android:debuggable flag to true in the
            AndroidManifest.

            :return:
        """

        xml = self._get_android_manifest()
        root = xml.getroot()

        click.secho('Setting debug flag to true', fg='green')

        application_tag = root.findall('application')

        # ensure that we got the application tag
        if len(application_tag) <= 0:
            message = 'Could not find the application tag in the AndroidManifest.xml'
            click.secho(message, fg='red', bold=True)
            raise Exception(message)

        application_tag = application_tag[0]

        if '{http://schemas.android.com/apk/res/android}debuggable' in application_tag.attrib \
                and application_tag.attrib['{http://schemas.android.com/apk/res/android}debuggable'] == 'true':
            click.secho('Application already has the android:debuggable flag set to True')
            return

        # set the debuggable flag
        application_tag.attrib['android:debuggable'] = 'true'

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

        # if no constructor is present, the full_load_library is used
        full_load_library = ('.method static constructor <clinit>()V\n'
                             '   .locals 1\n'
                             '\n'
                             '   .prologue\n'
                             '   const-string v0, "frida-gadget"\n'
                             '\n'
                             '   invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n'
                             '\n'
                             '   return-void\n'
                             '.end method\n')

        # if an existing constructor is present, this partial_load_library
        # will be used instead
        partial_load_library = ('    const-string v0, "frida-gadget"\n'
                                '\n'
                                '    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n')

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
        # want to inject right below the comment we matched
        inject_marker = inject_marker[0] + 1

        # Check if there is an existing clinit here. If there is, then we need
        # to determine where the constructor ends and inject a simple loadLibrary
        # just before the end
        if 'clinit' in smali_lines[inject_marker]:
            click.secho('Injecting into an existing constructor', fg='yellow')

            # need to find the end of the existing call. so, enumerate all of
            # the lines in the orignal smali sources and mark the offsets of the
            # lines that contain '.end method'. the search starts right after the
            # original inject marker so that we can pick the top most .end method
            # when we are done searching. this is also why the # represented in the
            # inject marker is added to the calculated marker in the list of end methods.
            end_methods = [(i + inject_marker) for i, x in enumerate(smali_lines[inject_marker:]) if '.end method' in x]

            # ensure that we found at least one .end method
            if len(end_methods) <= 0:
                raise Exception('Unable to find the end of the constructor')

            # set the last line of the constructors method to the one
            # just before the .end method line
            end_of_constructor = end_methods[0] - 1

            # check if the constructor has a return type call. if it does,
            # move up one line again to inject our loadLibrary before the return
            if 'return' in smali_lines[end_of_constructor]:
                end_of_constructor -= 1

            click.secho('Injecting loadLibrary call at line: {0}'.format(end_of_constructor), dim=True, fg='green')

            patched_smali = \
                smali_lines[:end_of_constructor] + partial_load_library.splitlines(keepends=True) + \
                smali_lines[end_of_constructor:]

        else:

            # if there is no constructor, we can simply inject a fresh constructor
            click.secho('Injecting loadLibrary call at line: {0}'.format(inject_marker), dim=True, fg='green')

            # inject the load_library code between
            patched_smali = \
                smali_lines[:inject_marker] + full_load_library.splitlines(keepends=True) + smali_lines[inject_marker:]

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
        o = delegator.run(list2cmdline([
            self.required_commands['apktool']['location'],
            'build',
            self.apk_temp_directory,
            '-o',
            self.apk_temp_frida_patched
        ]), timeout=self.command_run_timeout)

        if len(o.err) > 0:
            click.secho(('Rebuilding the APK may have failed. Read the following '
                         'output to determine if apktool actually had an error: \n'), fg='red')
            click.secho(o.err, fg='red')

        click.secho('Built new APK with injected loadLibrary and frida-gadget', fg='green')

    def zipalign_apk(self):
        """
            Performs the zipalign command on an APK.

            :return:
        """

        click.secho('Performing zipalign', dim=True)

        o = delegator.run(list2cmdline([
            self.required_commands['zipalign']['location'],
            '-p',
            '4',
            self.apk_temp_frida_patched,
            self.apk_temp_frida_patched_aligned
        ]))

        if len(o.err) > 0:
            click.secho(('Zipaligning the APK may have failed. Read the following '
                         'output to determine if zipalign actually had an error: \n'), fg='red')
            click.secho(o.err, fg='red')

        click.secho('Zipaling completed', fg='green')

    def sign_apk(self):
        """
            Signs an APK with the objection key.

            The keystore itself was created with:
                keytool -genkey -v -keystore objection.jks -alias objection -keyalg RSA -keysize 2048 -validity 3650
                pass: basil-joule-bug

            :return:
        """

        click.secho('Signing new APK.', dim=True)

        o = delegator.run(list2cmdline([
            self.required_commands['jarsigner']['location'],
            '-sigalg',
            'SHA1withRSA',
            '-digestalg',
            'SHA1',
            '-tsa',
            'http://timestamp.digicert.com',
            '-storepass',
            'basil-joule-bug',
            '-keystore',
            self.keystore,
            self.apk_temp_frida_patched,
            'objection'
        ]))

        if len(o.err) > 0 or 'jar signed' not in o.out:
            click.secho('Signing the new APK may have failed.', fg='red')
            click.secho(o.out, fg='yellow')
            click.secho(o.err, fg='red')

        click.secho('Signed the new APK', fg='green')

    def __del__(self):
        """
            Cleanup after ourselves.

            :return:
        """

        if self.skip_cleanup:
            click.secho('Not cleaning up temporary files', dim=True)
            return

        click.secho('Cleaning up temp files...', dim=True)

        try:

            shutil.rmtree(self.apk_temp_directory, ignore_errors=True)
            os.remove(self.apk_temp_frida_patched)
            os.remove(self.apk_temp_frida_patched_aligned)

        except Exception as err:
            click.secho('Failed to cleanup with error: {0}'.format(err), fg='red')
