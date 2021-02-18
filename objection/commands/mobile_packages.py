import os
import shutil

import click
import delegator
from pkg_resources import parse_version

from ..utils.patchers.android import AndroidGadget, AndroidPatcher
from ..utils.patchers.github import Github
from ..utils.patchers.ios import IosGadget, IosPatcher


def patch_ios_ipa(source: str, codesign_signature: str, provision_file: str, binary_name: str,
                  skip_cleanup: bool, unzip_unicode: bool, gadget_version: str = None,
                  pause: bool = False, gadget_config: str = None, script_source: str = None) -> None:
    """
        Patches an iOS IPA by extracting, injecting the Frida dylib,
        codesigning the dylib and app executable and rezipping the IPA.

        :param source:
        :param codesign_signature:
        :param provision_file:
        :param binary_name:
        :param skip_cleanup:
        :param unzip_unicode:
        :param gadget_version:
        :param pause:
        :param gadget_config:
        :param script_source:
        :return:
    """

    github = Github(gadget_version=gadget_version)
    ios_gadget = IosGadget(github)

    # get the gadget version numbers
    # check if a gadget version was specified. if not, get the latest one.
    if gadget_version is not None:
        github_version = gadget_version
        click.secho('Using manually specified version: {0}'.format(gadget_version), fg='green', bold=True)
    else:
        github_version = github.get_latest_version()
        click.secho('Using latest Github gadget version: {0}'.format(github_version), fg='green', bold=True)

    # get the local version number of the stored gadget
    local_version = ios_gadget.get_local_version('ios_universal')

    # check if the local version needs updating. this can be either because
    # the version is outdated or we simply don't have the gadget yet
    if parse_version(github_version) != parse_version(local_version) or not ios_gadget.gadget_exists():
        # download!
        click.secho('Remote FridaGadget version is v{0}, local is v{1}. Downloading...'.format(
            github_version, local_version), fg='green')

        # download, unpack, update local version and cleanup the temp files.
        ios_gadget.download() \
            .unpack() \
            .set_local_version('ios_universal', github_version) \
            .cleanup()

    click.secho('Patcher will be using Gadget version: {0}'.format(github_version), fg='green')

    # start the patching process
    patcher = IosPatcher(skip_cleanup=skip_cleanup)

    # return of we do not have all of the requirements.
    if not patcher.are_requirements_met():
        return

    patcher.set_provsioning_profile(provision_file=provision_file)
    patcher.extract_ipa(unzip_unicode, ipa_source=source)
    patcher.set_application_binary(binary=binary_name)
    patcher.patch_and_codesign_binary(
        frida_gadget=ios_gadget.get_gadget_path(), codesign_signature=codesign_signature, gadget_config=gadget_config)

    if script_source:
        click.secho('Copying over a custom script to use with the gadget config.', fg='green')
        shutil.copyfile(script_source, os.path.join(patcher.app_folder, 'Frameworks', script_source))

    # give a chance to make any last minute modifications if needed
    if pause:
        click.secho(('Patching paused. The next step is to rebuild the IPA. '
                     'If you require any manual fixes, the current temp '
                     'directory is:'), bold=True)
        click.secho('{0}'.format(patcher.app_folder), fg='green', bold=True)

        input('Press ENTER to continue...')

    patcher.archive_and_codesign(original_name=source, codesign_signature=codesign_signature)

    click.secho('Copying final ipa from {0} to current directory...'.format(patcher.get_patched_ipa_path()))
    shutil.copyfile(
        patcher.get_patched_ipa_path(),
        os.path.join(os.path.abspath('.'), os.path.basename(patcher.get_patched_ipa_path())))


def patch_android_apk(source: str, architecture: str, pause: bool, skip_cleanup: bool = True,
                      enable_debug: bool = True, gadget_version: str = None, skip_resources: bool = False,
                      network_security_config: bool = False, target_class: str = None,
                      use_aapt2: bool = False, gadget_config: str = None, script_source: str = None,
                      ignore_nativelibs: bool = True, manifest: str = None) -> None:
    """
        Patches an Android APK by extracting, patching SMALI, repackaging
        and signing a new APK.

        :param source:
        :param architecture:
        :param pause:
        :param skip_cleanup:
        :param enable_debug:
        :param gadget_version:
        :param skip_resources:
        :param network_security_config:
        :param target_class:
        :param use_aapt2:
        :param gadget_config:
        :param script_source:
        :param manifest:

        :return:
    """

    github = Github(gadget_version=gadget_version)
    android_gadget = AndroidGadget(github)

    # without an architecture set, attempt to determine one using adb
    if not architecture:
        click.secho('No architecture specified. Determining it using `adb`...', dim=True)
        o = delegator.run('adb shell getprop ro.product.cpu.abi')

        # read the ach from the process' output
        architecture = o.out.strip()

        if len(architecture) <= 0:
            click.secho('Failed to determine architecture. Is the device connected and authorized?',
                        fg='red', bold=True)
            return

        click.secho('Detected target device architecture as: {0}'.format(architecture), fg='green', bold=True)

    # set the architecture we are interested in
    android_gadget.set_architecture(architecture)

    # check the gadget config flags
    if script_source and not gadget_config:
        click.secho('A script source was specified but no gadget configuration was set.', fg='red', bold=True)
        return

    # check if a gadget version was specified. if not, get the latest one.
    if gadget_version is not None:
        github_version = gadget_version
        click.secho('Using manually specified version: {0}'.format(gadget_version), fg='green', bold=True)
    else:
        github_version = github.get_latest_version()
        click.secho('Using latest Github gadget version: {0}'.format(github_version), fg='green', bold=True)

    # get local version of the stored gadget
    local_version = android_gadget.get_local_version('android_' + architecture)

    # check if the local version needs updating. this can be either because
    # the version is outdated or we simply don't have the gadget yet, or, we want
    # a very specific version
    if parse_version(github_version) != parse_version(local_version) or not android_gadget.gadget_exists():
        # download!
        click.secho('Remote FridaGadget version is v{0}, local is v{1}. Downloading...'.format(
            github_version, local_version), fg='green')

        # download, unpack, update local version and cleanup the temp files.
        android_gadget.download() \
            .unpack() \
            .set_local_version('android_' + architecture, github_version) \
            .cleanup()

    click.secho('Patcher will be using Gadget version: {0}'.format(github_version), fg='green')

    patcher = AndroidPatcher(skip_cleanup=skip_cleanup, skip_resources=skip_resources, manifest=manifest)

    # ensure that we have all of the commandline requirements
    if not patcher.are_requirements_met():
        return
    
    # ensure we have the latest apk-tool and run the
    if not patcher.is_apktool_ready():
        click.secho('apktool is not ready for use', fg='red', bold=True)
        return

    # work on patching the APK
    patcher.set_apk_source(source=source)
    patcher.unpack_apk()
    patcher.inject_internet_permission()

    if not ignore_nativelibs:
        patcher.extract_native_libs_patch()

    if enable_debug:
        patcher.flip_debug_flag_to_true()

    if network_security_config:
        patcher.add_network_security_config()

    patcher.inject_load_library(target_class=target_class)
    patcher.add_gadget_to_apk(architecture, android_gadget.get_frida_library_path(), gadget_config)

    if script_source:
        click.secho('Copying over a custom script to use with the gadget config.', fg='green')
        shutil.copyfile(script_source,
                        os.path.join(patcher.apk_temp_directory, 'lib', architecture,
                                     'libfrida-gadget.script.so'))

    # if we are required to pause, do that.
    if pause:
        click.secho(('Patching paused. The next step is to rebuild the APK. '
                     'If you require any manual fixes, the current temp '
                     'directory is:'), bold=True)
        click.secho('{0}'.format(patcher.get_temp_working_directory()), fg='green', bold=True)

        input('Press ENTER to continue...')

    patcher.build_new_apk(use_aapt2=use_aapt2)
    patcher.zipalign_apk()
    patcher.sign_apk()

    # woohoo, get the APK!
    destination = source.replace('.apk', '.objection.apk')

    click.secho(
        'Copying final apk from {0} to {1} in current directory...'.format(patcher.get_patched_apk_path(), destination))
    shutil.copyfile(patcher.get_patched_apk_path(), os.path.join(os.path.abspath('.'), destination))

def sign_android_apk(source: str, skip_cleanup: bool = True) -> None:
    """
        Zipaligns and signs an Android APK with the objection key.

        :param source:
        :param skip_cleanup:

        :return:
    """

    patcher = AndroidPatcher(skip_cleanup=skip_cleanup)

    # ensure that we have all of the commandline requirements
    if not patcher.are_requirements_met():
        return

    patcher.set_apk_source(source=source)
    patcher.zipalign_apk()
    patcher.sign_apk()

    # woohoo, get the APK!
    destination = source.replace('.apk', '.objection.apk')

    click.secho(
        'Copying final apk from {0} to {1} in current directory...'.format(patcher.get_patched_apk_path(), destination))
    shutil.copyfile(patcher.get_patched_apk_path(), os.path.join(os.path.abspath('.'), destination))
