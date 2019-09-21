import os
import json

import click
from tabulate import tabulate

from objection.state.connection import state_connection
from ..utils.helpers import clean_argument_flags
from ..utils.helpers import sizeof_fmt, pretty_concat


def _is_string_input(args: list) -> bool:
    """
        Checks if --string is in the list of tokens received form the
        command line.

        :param args:
        :return:
    """

    return len(args) > 0 and '--string' in args


def _should_only_dump_offsets(args: list) -> bool:
    """
        Checks if --offsets-only is in the list pf tokens received
        from the command line.

        :param args:
        :return:
    """

    return '--offsets-only' in args


def _should_output_json(args: list) -> bool:
    """
        Checks if --json is in the list of tokens received from the command line.

        :param args:
        :return:
    """

    return len(args) > 0 and '--json' in args


# TODO: Dump memory on hooked methods.
# A PR in the repo this method is based on has an idea for this
#
# https://github.com/Nightbringer21/fridump/pull/3

def dump_all(args: list) -> None:
    """
        Dump memory from the currently injected process.
        Loosely based on:
            https://github.com/Nightbringer21/fridump

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) <= 0:
        click.secho('Usage: memory dump all <local destination>', bold=True)
        return

    # the destination file to write the dump to
    destination = args[0]

    # Check for file override
    if os.path.exists(destination):
        click.secho('Destination file {dest} already exists'.format(dest=destination), fg='yellow', bold=True)
        if not click.confirm('Continue, appending to the file?'):
            return

    # access type used when enumerating ranges
    access = 'rw-'

    api = state_connection.get_api()
    ranges = api.memory_list_ranges(access)

    total_size = sum([x['size'] for x in ranges])
    click.secho('Will dump {0} {1} images, totalling {2}'.format(
        len(ranges), access, sizeof_fmt(total_size)), fg='green', dim=True)

    with click.progressbar(ranges) as bar:
        for image in bar:
            bar.label = 'Dumping {0} from base: {1}'.format(sizeof_fmt(image['size']), hex(int(image['base'], 16)))

            # catch and exception thrown while dumping.
            # this could for a few reasons like if the protection
            # changes or the range is reallocated
            try:
                # grab the (size) bytes starting at the (base_address)
                dump = api.memory_dump(int(image['base'], 16), image['size'])
            except Exception:
                continue

            # append the results to the destination file
            with open(destination, 'ab') as f:
                f.write(dump)

    click.secho('Memory dumped to file: {0}'.format(destination), fg='green')


def dump_from_base(args: list) -> None:
    """
        Dump memory from a base address for a specific size to file

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) < 3:
        click.secho('Usage: memory dump from_base <base_address> <size_to_dump> <local_destination>', bold=True)
        return

    # the destination file to write the dump to
    base_address = args[0]
    memory_size = args[1]
    destination = args[2]

    # Check for file override
    if os.path.exists(destination):
        click.secho('Destination file {dest} already exists'.format(dest=destination), fg='yellow', bold=True)
        if not click.confirm('Override?'):
            return

    click.secho('Dumping {0} from {1} to {2}'.format(sizeof_fmt(int(memory_size)), base_address, destination),
                fg='green', dim=True)

    api = state_connection.get_api()
    dump = api.memory_dump(int(base_address, 16), int(memory_size))

    # append the results to the destination file
    with open(destination, 'wb') as f:
        f.write(dump)

    click.secho('Memory dumped to file: {0}'.format(destination), fg='green')


def list_modules(args: list = None) -> None:
    """
        List modules loaded in the current process.

        :param args:
        :return:
    """

    if _should_output_json(args) and len(args) < 2:
        click.secho('Usage: memory list modules (--json <local destination>)', bold=True)
        return

    if not _should_output_json(args):
        click.secho('Save the output by adding `--json modules.json` to this command', dim=True)

    api = state_connection.get_api()
    modules = api.memory_list_modules()

    if _should_output_json(args):
        destination = args[args.index('--json') + 1]

        click.secho('Writing modules as json to {0}...'.format(destination), dim=True)

        with open(destination, 'w') as f:
            f.write(json.dumps(modules, indent=2))

        click.secho('Wrote modules to: {0}'.format(destination), fg='green')
        return

    # Just dump it to the screen
    click.secho(tabulate(
        [[
            entry['name'],
            entry['base'],
            str(entry['size']) + ' (' + sizeof_fmt(entry['size']) + ')',
            pretty_concat(entry['path']),
        ] for entry in modules], headers=['Name', 'Base', 'Size', 'Path'],
    ))


def list_exports(args: list) -> None:
    """
        Dumps the exported methods from a loaded module to screen.

        :param args:
        :return:
    """

    if _should_output_json(args) and len(args) < 3:
        click.secho('Usage: memory list exports <module name> (--json <local destination>)', bold=True)
        return

    if not _should_output_json(args):
        click.secho('Save the output by adding `--json exports.json` to this command', dim=True)

    if len(clean_argument_flags(args)) <= 0:
        click.secho('Usage: memory list exports <module name>', bold=True)
        return

    module_to_list = args[0]

    api = state_connection.get_api()
    exports = api.memory_list_exports(module_to_list)

    if _should_output_json(args):
        destination = args[args.index('--json') + 1]

        click.secho('Writing exports as json to {0}...'.format(destination), dim=True)

        with open(destination, 'w') as f:
            f.write(json.dumps(exports, indent=2))

        click.secho('Wrote exports to: {0}'.format(destination), fg='green')
        return

    # Just dump it to the screen
    click.secho(tabulate(
        [[
            entry['type'],
            entry['name'],
            entry['address'],
        ] for entry in exports], headers=['Type', 'Name', 'Address'],
    ))


def find_pattern(args: list) -> None:
    """
        Searches the current processes accessible memory for a specific pattern.

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) <= 0:
        click.secho('Usage: memory search "<pattern eg: 41 41 41 ?? 41>" (--string) (--offsets-only)', bold=True)
        return

    # if we got a string as input, convert it to hex
    if _is_string_input(args):
        pattern = ' '.join(hex(ord(x))[2:] for x in args[0])
    else:
        pattern = args[0]

    click.secho('Searching for: {0}'.format(pattern), dim=True)

    api = state_connection.get_api()
    data = api.memory_search(pattern, _should_only_dump_offsets(args))

    if len(data) > 0:
        click.secho('Pattern matched at {0} addresses'.format(len(data)), fg='green')
        if _should_only_dump_offsets(args):
            for address in data:
                click.secho(address)

    else:
        click.secho('Unable to find the pattern in any memory region')


def write(args: list) -> None:
    """
        Write an arbitrary amount of bytes to an arbitrary memory address.

        Needless to say, use with caution. =P

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) < 2:
        click.secho('Usage: memory write "<address>" "<pattern eg: 41 41 41 41>" (--string)', bold=True)
        return

    destination = args[0]
    pattern = args[1]

    if _is_string_input(args):
        pattern = [ord(x) for x in pattern]
    else:
        pattern = [int(x, 16) for x in pattern.split(' ')]

    click.secho('Writing byte array: {0} to {1}'.format(pattern, destination), dim=True)

    api = state_connection.get_api()
    api.memory_write(destination, pattern)
