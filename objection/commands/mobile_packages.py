import os
import shutil

import click
from pkg_resources import parse_version

from ..utils.packages import Github, IosGadget, IosPatcher


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

    # check if the local version needs updating
    if parse_version(github.get_latest_version()) > parse_version(ios_gadget.get_local_version()):
        click.secho('Github FridaGadget is v{0}, local is v{1}. Updating...'.format(
            github.get_latest_version(), ios_gadget.get_local_version()), fg='green')

        # download, unpack, update local version and cleanup the temp files.
        ios_gadget.download() \
            .unpack() \
            .set_local_version(github.get_latest_version()) \
            .cleanup()

    click.secho('Using Gadget version: {0}'.format(ios_gadget.get_local_version()), fg='green')

    # start the patching process
    patcher = IosPatcher()

    # return of we do not have all of the requirements.
    if not patcher.are_requirements_met():
        return

    patcher.set_provsioning_profile()
    patcher.extract_ipa(ipa_source=source)
    patcher.set_application_binary(binary=binary_name)
    patcher.patch_and_codesign_binary(
        frida_gadget=ios_gadget.get_gadget_path(), codesign_signature=codesign_signature)
    patcher.archive_and_codesign(original_name=source, codesign_signature=codesign_signature)

    click.secho('Copying final ipa from {0} to current directory...'.format(patcher.get_patched_ipa_path()))
    shutil.copyfile(
        patcher.get_patched_ipa_path(),
        os.path.join(os.path.abspath('.'), os.path.basename(patcher.get_patched_ipa_path())))
