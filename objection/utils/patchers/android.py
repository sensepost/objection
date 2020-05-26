import lzma
import os
import shutil
import tempfile
import xml.etree.ElementTree as ElementTree
from pkg_resources import parse_version
import re

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
            'installation': 'apt install default-jdk (Linux); brew cask install java (macOS)'
        },
        'apktool': {
            'installation': 'apt install apktool (Kali Linux)'
        },
        'zipalign': {
            'installation': 'apt install zipalign'
        }
    }

    def __init__(self, skip_cleanup: bool = False, skip_resources: bool = False):
        super(AndroidPatcher, self).__init__()

        self.apk_source = None
        self.apk_temp_directory = tempfile.mkdtemp(suffix='.apktemp')
        self.apk_temp_frida_patched = self.apk_temp_directory + '.objection.apk'
        self.apk_temp_frida_patched_aligned = self.apk_temp_directory + '.aligned.objection.apk'
        self.aapt = None
        self.skip_cleanup = skip_cleanup
        self.skip_resources = skip_resources

        self.keystore = os.path.join(os.path.abspath(os.path.dirname(__file__)), '../assets', 'objection.jks')
        self.netsec_config = os.path.join(os.path.abspath(os.path.dirname(__file__)), '../assets',
                                          'network_security_config.xml')

    def is_apktool_ready(self) -> bool:
        """
            Check if apktool is ready for use.

            :return:bool
        """

        min_version = '2.4.1'  # the version of apktool we require

        o = delegator.run(self.list2cmdline([
            self.required_commands['apktool']['location'],
            '-version',
        ]), timeout=self.command_run_timeout).out.strip()

        # On windows we get this 'Press any key to continue' thing,
        # localized to the the current language. Assume that the version
        # string we want is always the first line.
        if len(o.split('\n')) > 1:
            o = o.split('\n')[0]

        if len(o) == 0:
            click.secho('Unable to determine apktool version. Is it installed')
            return False

        click.secho('Detected apktool version as: ' + o, dim=True)

        # ensure we have at least apktool MIN_VERSION
        if parse_version(o) < parse_version(min_version):
            click.secho('apktool version should be at least ' + min_version, fg='red', bold=True)
            click.secho('Please see the following URL for more information: '
                        'https://github.com/sensepost/objection/wiki/Apktool-Upgrades', fg='yellow')
            return False

        # run clean-frameworks-dir
        click.secho('Running apktool empty-framework-dir...', dim=True)
        o = delegator.run(self.list2cmdline([
            self.required_commands['apktool']['location'],
            'empty-framework-dir',
        ]), timeout=self.command_run_timeout).out.strip()

        if len(o) > 0:
            click.secho(o, fg='yellow', dim=True)

        return True

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

        # error if --skip-resources was used because the manifest is encoded
        if self.skip_resources is True:
            click.secho('Cannot manually parse the AndroidManifest.xml when --skip-resources '
                        'is set, remove this and try again.', fg='red')
            raise Exception('Cannot --skip-resources when trying to manually parse the AndroidManifest.xml')

        # use the android namespace
        ElementTree.register_namespace('android', 'http://schemas.android.com/apk/res/android')

        return ElementTree.parse(os.path.join(self.apk_temp_directory, 'AndroidManifest.xml'))

    def _get_appt_output(self):
        """
            Get the output of `aapt dump badging`.

            :return:
        """

        if not self.aapt:
            o = delegator.run(self.list2cmdline([
                self.required_commands['aapt']['location'],
                'dump',
                'badging',
                self.apk_source
            ]), timeout=self.command_run_timeout)

            if len(o.err) > 0:
                click.secho('An error may have occurred while running aapt.', fg='red')
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

        activities = (match.groups()[0] for match in re.finditer(r"^launchable-activity: name='([^']+)'", self._get_appt_output(), re.MULTILINE))
        activity = next(activities, None)

        # If we got the activity using aapt, great, return that
        if activity is not None:
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

    def unpack_apk(self):
        """
            Unpack an APK with apktool.

            :return:
        """

        click.secho('Unpacking {0}'.format(self.apk_source), dim=True)

        o = delegator.run(self.list2cmdline([
            self.required_commands['apktool']['location'],
            'decode',
            '-f',
            '-r' if self.skip_resources else '',
            '-o',
            self.apk_temp_directory,
            self.apk_source
        ]), timeout=self.command_run_timeout)

        if len(o.err) > 0:
            click.secho('An error may have occurred while extracting the APK.', fg='red')
            click.secho(o.err, fg='red')

    def inject_internet_permission(self):
        """
            Checks the status of the source APK to see if it
            has the INTERNET permission. If not, the manifest file
            is parsed and the permission injected.

            :return:
        """

        internet_permission = 'android.permission.INTERNET'

        # if the app already has the internet permission, easy mode :D
        if internet_permission in self._get_appt_output():
            click.secho('App already has android.permission.INTERNET', fg='green')
            return

        # if not, we need to inject an element with it
        click.secho('App does not have android.permission.INTERNET, attempting to patch the AndroidManifest.xml...', dim=True, fg='yellow')
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

    def extract_native_libs_patch(self):
        """
            Check the AndroidManifest.xml file for extractNativeLibs="false"
            if it exists, change it to extractNativeLibs="true".

            Since AndroidStudio 2.1 this flag is set as false by default.
            This breaks it when installing the .apk to the device.

            :return:
        """
        xml = self._get_android_manifest()
        root = xml.getroot()

        application_tag = root.findall('application')

        # ensure that we got the application tag
        if len(application_tag) <= 0:
            message = 'Could not find the application tag in the AndroidManifest.xml'
            click.secho(message, fg='red', bold=True)
            raise Exception(message)

        application_tag = application_tag[0]

        # Check if the flag is present and set to false
        if '{http://schemas.android.com/apk/res/android}extractNativeLibs' in application_tag.attrib \
                and application_tag.attrib['{http://schemas.android.com/apk/res/android}extractNativeLibs'] == 'false':
            # Set the flag to true
            application_tag.attrib['{http://schemas.android.com/apk/res/android}extractNativeLibs'] = 'true'
            click.secho('Setting extractNativeLibs to true...', dim=True)
            xml.write(os.path.join(self.apk_temp_directory, 'AndroidManifest.xml'),
                      encoding='utf-8', xml_declaration=True)
            return

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
        application_tag.attrib['{http://schemas.android.com/apk/res/android}debuggable'] = 'true'

        click.secho('Writing new Android manifest...', dim=True)
        xml.write(os.path.join(self.apk_temp_directory, 'AndroidManifest.xml'),
                  encoding='utf-8', xml_declaration=True)

    def add_network_security_config(self):
        """
            Add a network_security_config.xml to the AndroidManifest.xml for
            Android 7+.

            Refs:
                https://serializethoughts.com/2016/09/10/905/
                https://warroom.securestate.com/android-7-intercepting-app-traffic/
                https://www.nowsecure.com/blog/2017/06/15/certificate-pinning-for-android-and-ios-mobile-man-in-the-middle-attack-prevention/
                https://android-developers.googleblog.com/2016/07/changes-to-trusted-certificate.html
                https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2017/november/bypassing-androids-network-security-configuration/
                https://sensepost.com/blog/2018/tip-toeing-past-android-7s-network-security-configuration/

            return:
        """

        xml = self._get_android_manifest()
        root = xml.getroot()
        application_tag = root.findall('application')

        # ensure that we got the application tag
        if len(application_tag) <= 0:
            message = 'Could not find the application tag in the AndroidManifest.xml'
            click.secho(message, fg='red', bold=True)
            raise Exception(message)

        application_tag = application_tag[0]

        click.secho('Checking for an existing networkSecurityConfig tag', dim=True)

        if '{http://schemas.android.com/apk/res/android}networkSecurityConfig' in application_tag.attrib:
            if not click.prompt('An existing network security config was found. Do you want to replace it?',
                                type=bool, default=True):
                return

        # copy our network security configuration to res/xml/network_security_config.xml
        sec_config_path = os.path.join(self.apk_temp_directory, 'res', 'xml')

        # check if the config path exists
        if not os.path.exists(sec_config_path):
            click.secho('Creating XML res path: {0}'.format(sec_config_path), dim=True)
            os.makedirs(sec_config_path)

        click.secho('Copying network_security_config.xml...', fg='green', dim=True)
        shutil.copyfile(self.netsec_config, os.path.join(sec_config_path, 'network_security_config.xml'))

        # set the networkSecurityConfig xml location
        # this is in res/xml/network_security_config.xml
        application_tag.attrib[
            '{http://schemas.android.com/apk/res/android}networkSecurityConfig'] = '@xml/network_security_config'

        click.secho('Writing new Android manifest...', dim=True)
        xml.write(os.path.join(self.apk_temp_directory, 'AndroidManifest.xml'),
                  encoding='utf-8', xml_declaration=True)

    def _determine_smali_path_for_class(self, target_class) -> str:
        """
            Attempts to determine the local path for a target class' smali

            :param target_class:
            :return:
        """

        # convert to a filesystem path, just like how it would be on disk
        # from the apktool dump
        target_class = target_class.replace('.', '/')

        activity_path = os.path.join(self.apk_temp_directory, 'smali', target_class) + '.smali'

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
                activity_path = os.path.join(smali_path, target_class) + '.smali'

                # if we found the activity, stop the loop
                if os.path.exists(activity_path):
                    click.secho('Found smali at: {0}'.format(activity_path), dim=True)
                    break

        # one final check to ensure we have the target .smali file
        if not os.path.exists(activity_path):
            raise Exception('Unable to find smali to patch!')

        return activity_path

    @staticmethod
    def _determine_end_of_smali_method_from_line(smali: list, start: int) -> int:
        """
            Determines where the .end method line is.

            This method is also aware of a methods that 'returns' and will
            return the line before that too.

            :param smali:
            :param start:
            :return:
        """

        # enumerate all of # the lines in the original smali sources and mark the offsets of the
        # lines that contain '.end method'. the search starts right after the
        # original inject marker so that we can pick the top most .end method
        # when we are done searching. this is also why the # represented in the
        # inject marker is added to the calculated marker in the list of end methods.
        end_methods = [(i + start) for i, x in enumerate(smali[start:]) if '.end method' in x]

        # ensure that we found at least one .end method
        if len(end_methods) <= 0:
            raise Exception('Unable to find the end of the existing constructor')

        # set the last line of the constructors method to the one
        # just before the .end method line
        end_of_method = end_methods[0] - 1

        # check if the constructor has a return type call. if it does,
        # move up one line again to inject our loadLibrary before the return
        if 'return' in smali[end_of_method]:
            end_of_method -= 1

        return end_of_method

    def _patch_smali_with_load_library(self, smali_lines: list, inject_marker: int) -> list:
        """
            Patches a list of smali lines with the appropriate
            loadLibrary call based on wether a constructor already
            exists or not.

            :param smali_lines:
            :param inject_marker:
            :return:
        """

        # raw smali to inject.
        # ref: https://koz.io/using-frida-on-android-without-root/

        # if no constructor is present, the full_load_library is used
        full_load_library = ('.method static constructor <clinit>()V\n'
                             '   .locals 0\n'  # _revalue_locals_count() will ++ this
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
        partial_load_library = ('\n    const-string v0, "frida-gadget"\n'
                                '\n'
                                '    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n')

        # Check if there is an existing clinit here. If there is, then we need
        # to determine where the constructor ends and inject a simple loadLibrary
        # just before the end
        if 'clinit' in smali_lines[inject_marker]:
            click.secho('Injecting into an existing constructor', fg='yellow')

            end_of_constructor = self._determine_end_of_smali_method_from_line(smali_lines, inject_marker)
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

        return patched_smali

    def _revalue_locals_count(self, patched_smali: list, inject_marker: int):
        """
            Attempt to ++ the first .locals declaration in a list of
            smali lines confined to the same method.

            :param patched_smali:
            :param inject_marker:
            :return:
        """

        def _h():
            click.secho('Could not update .locals value. Sometimes this may break things,'
                        'but not always. If the applications crashes after patching, try '
                        'and add the --pause flag, fixing the patched smali manually.', fg='yellow')

        # next, update the .locals count (if its defined)
        # if this step fails, its not really a big deal as many times its not
        # fatal. however, if it does fail, warn about it.
        click.secho('Attempting to fix the constructors .locals count', dim=True)
        end_of_method = self._determine_end_of_smali_method_from_line(patched_smali, inject_marker)

        # check if we have a .locals declaration right after the start of our
        # already matched constructor
        defined_locals = [i for i, x in enumerate(patched_smali[inject_marker:end_of_method])
                          if '.locals' in x]

        if len(defined_locals) <= 0:
            click.secho('Unable to determine any .locals for the target constructor', fg='yellow')
            _h()
            return patched_smali

        # determine the offset for the first matched .locals definition
        locals_smali_offset = defined_locals[0] + inject_marker

        try:
            defined_local_value = patched_smali[locals_smali_offset].split(' ')[-1]
            defined_local_value_as_int = int(defined_local_value, 10)
            new_locals_value = defined_local_value_as_int + 1

        except ValueError as e:
            click.secho(
                'Unable to parse .locals value for the injected constructor with error: {0}'.format(str(e)),
                fg='yellow')
            _h()

            return patched_smali

        click.secho('Current locals value is {0}, updating to {1}:'.format(
            defined_local_value_as_int, new_locals_value), dim=True)

        # simply search / replace the integer values we already calculated on the relevant line
        patched_smali[locals_smali_offset] = patched_smali[locals_smali_offset].replace(
            str(defined_local_value_as_int), str(new_locals_value))

        return patched_smali

    def inject_load_library(self, target_class: str = None):
        """
            Injects a loadLibrary call into a class.
            If a target class is not specified, we will make an attempt
            at searching for a launchable activity in the target APK.

            Most of the idea for this comes from:
                https://koz.io/using-frida-on-android-without-root/

            :return:
        """

        # determine the path to the smali we should inject the load_library
        # call into. a user may specify a specific class to target, otherwise
        # we get a class name from the internal launchable activity method
        # of this class.

        if target_class:
            click.secho('Using target class: {0} for patch'.format(target_class), fg='green', bold=True)
        else:
            click.secho('Target class not specified, searching for launchable activity instead...', fg='green',
                        bold=True)

        activity_path = self._determine_smali_path_for_class(
            target_class if target_class else self._get_launchable_activity())

        click.secho('Reading smali from: {0}'.format(activity_path), dim=True)

        # apktool d smali will have a comment line line: '# direct methods'
        with open(activity_path, 'r') as f:
            smali_lines = f.readlines()

        # search for the line starting with '# direct methods' in it
        inject_marker = [i for i, x in enumerate(smali_lines) if '# direct methods' in x]

        # ensure we got a marker
        if len(inject_marker) <= 0:
            raise Exception('Unable to determine position to inject a loadLibrary call')

        # pick the first position for the inject. add one line as we
        # want to inject right below the comment we matched
        inject_marker = inject_marker[0] + 1

        patched_smali = self._patch_smali_with_load_library(smali_lines, inject_marker)
        patched_smali = self._revalue_locals_count(patched_smali, inject_marker)

        click.secho('Writing patched smali back to: {0}'.format(activity_path), dim=True)

        with open(activity_path, 'w') as f:
            f.write(''.join(patched_smali))

    def add_gadget_to_apk(self, architecture: str, gadget_source: str, gadget_config: str):
        """
            Copies a frida gadget for a specific architecture to
            an extracted APK's lib path.

            :param architecture:
            :param gadget_source:
            :param gadget_config:
            :return:
        """

        libs_path = os.path.join(self.apk_temp_directory, 'lib', architecture)

        # check if the libs path exists
        if not os.path.exists(libs_path):
            click.secho('Creating library path: {0}'.format(libs_path), dim=True)
            os.makedirs(libs_path)

        click.secho('Copying Frida gadget to libs path...', fg='green', dim=True)
        shutil.copyfile(gadget_source, os.path.join(libs_path, 'libfrida-gadget.so'))

        if gadget_config:
            click.secho('Adding a gadget configuration file...', fg='green')
            shutil.copyfile(gadget_config, os.path.join(libs_path, 'libfrida-gadget.config.so'))

    def build_new_apk(self, use_aapt2: bool = False):
        """
            Build a new .apk with the frida-gadget patched in.

            :return:
        """

        click.secho('Rebuilding the APK with the frida-gadget loaded...', fg='green', dim=True)
        o = delegator.run(
            self.list2cmdline([self.required_commands['apktool']['location'],
                          'build',
                          self.apk_temp_directory,
                          ] + (['--use-aapt2'] if use_aapt2 else []) + [
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

        o = delegator.run(self.list2cmdline([
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

        click.secho('Zipalign completed', fg='green')

    def sign_apk(self):
        """
            Signs an APK with the objection key.

            The keystore itself was created with:
                keytool -genkey -v -keystore objection.jks -alias objection -keyalg RSA -keysize 2048 -validity 3650
                pass: basil-joule-bug

            :return:
        """

        click.secho('Signing new APK.', dim=True)

        o = delegator.run(self.list2cmdline([
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
            click.secho('Failed to cleanup with error: {0}'.format(err), fg='red', dim=True)
