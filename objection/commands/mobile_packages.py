import os
import shutil

import click
import delegator
from pkg_resources import parse_version

from ..utils.packages import Github, IosGadget, IosPatcher, AndroidGadget, AndroidPatcher


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

    github = Github()
    ios_gadget = IosGadget(github)

    # get the gadget version numbers
    github_version = github.get_latest_version()
    local_version = ios_gadget.get_local_version('ios_universal')

    # check if the local version needs updating. this can be either because
    # the version is outdated or we simply don't have the gadget yet
    if parse_version(github_version) > parse_version(local_version) or not ios_gadget.gadget_exists():
        # download!
        click.secho('Github FridaGadget is v{0}, local is v{1}. Updating...'.format(
            github_version, local_version), fg='green')

        # download, unpack, update local version and cleanup the temp files.
        ios_gadget.download() \
            .unpack() \
            .set_local_version('ios_universal', github_version) \
            .cleanup()

    click.secho('Using Gadget version: {0}'.format(github_version), fg='green')

    # start the patching process
    patcher = IosPatcher()

    # return of we do not have all of the requirements.
    if not patcher.are_requirements_met():
        return

    patcher.set_provsioning_profile(provision_file=provision_file)
    patcher.extract_ipa(ipa_source=source)
    patcher.set_application_binary(binary=binary_name)
    patcher.patch_and_codesign_binary(
        frida_gadget=ios_gadget.get_gadget_path(), codesign_signature=codesign_signature)
    patcher.archive_and_codesign(original_name=source, codesign_signature=codesign_signature)

    click.secho('Copying final ipa from {0} to current directory...'.format(patcher.get_patched_ipa_path()))
    shutil.copyfile(
        patcher.get_patched_ipa_path(),
        os.path.join(os.path.abspath('.'), os.path.basename(patcher.get_patched_ipa_path())))


def patch_android_apk(source: str, architecture: str) -> None:
    """
        Patches an Android APK by extracting, patching SMALI, repackaging
        and signing a new APK.

        :param source:
        :param architecture:
        :return:
    """

    github = Github()
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

        click.secho('Detected the architecture as: {0}'.format(architecture), fg='green', bold=True)

    # set the architecture we are interested in
    android_gadget.set_architecture(architecture)

    # get the gadget version numbers
    github_version = github.get_latest_version()
    local_version = android_gadget.get_local_version('android_' + architecture)

    # check if the local version needs updating. this can be either because
    # the version is outdated or we simply don't have the gadget yet
    if parse_version(github_version) > parse_version(local_version) or not android_gadget.gadget_exists():
        # download!
        click.secho('Github FridaGadget is v{0}, local is v{1}. Updating...'.format(
            github_version, local_version), fg='green')

        # download, unpack, update local version and cleanup the temp files.
        android_gadget.download() \
            .unpack() \
            .set_local_version('android_' + architecture, github.get_latest_version()) \
            .cleanup()

    click.secho('Using Gadget version: {0}'.format(github_version), fg='green')

    patcher = AndroidPatcher()

    # ensure that we have all of the commandline requirements
    if not patcher.are_requirements_met():
        return

    # work on patching the APK
    patcher.set_apk_source(source=source)
    patcher.unpack_apk()
    patcher.inject_internet_permission()
    patcher.inject_load_library()
    patcher.add_gadget_to_apk(architecture, android_gadget.get_frida_library_path())
    patcher.build_new_apk()
    patcher.sign_apk()

    # woohoo, get the APK!
    click.secho('Copying final apk from {0} to current directory...'.format(patcher.get_patched_apk_path()))
    destination = ''.join(source.split('.')[:-1]) + '.objection.apk'
    shutil.copyfile(patcher.get_patched_apk_path(), os.path.join(os.path.abspath('.'), destination))
