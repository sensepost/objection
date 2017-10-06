import json
import os
import shutil

import click

from .github import Github

# default paths
objection_path = os.path.join(os.path.expanduser('~'), '.objection')
gadget_versions = os.path.join(objection_path, 'gadget_versions')


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
