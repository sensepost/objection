import click
from tabulate import tabulate

from ..utils.frida_transport import FridaRunner
from ..utils.helpers import clean_argument_flags
from ..utils.helpers import sizeof_fmt, pretty_concat
from ..utils.templates import generic_hook


def _is_string_input(args: list) -> bool:
    """
        Checks if --string is in the list of tokens received form the
        command line.

        :param args:
        :return:
    """

    return len(args) > 0 and '--string' in args


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

    # access type used when enumerating ranges
    access = 'rw-'

    runner = FridaRunner()
    session = runner.get_session()
    ranges = session.enumerate_ranges(access)

    total_size = sum([x.size for x in ranges])
    click.secho('Will dump {0} {1} images, totalling {2}'.format(
        len(ranges), access, sizeof_fmt(total_size)), fg='green', dim=True)

    with click.progressbar(ranges, label='Preparing to dump images') as bar:

        for image in bar:
            bar.label = 'Dumping {0} from base: {1}'.format(sizeof_fmt(image.size), hex(image.base_address))

            # grab the (size) bytes starting at the (base_address)
            dump = session.read_bytes(image.base_address, image.size)

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

    click.secho('Dumping {0} from {1} to {2}'.format(sizeof_fmt(int(memory_size)), base_address, destination),
                fg='green', dim=True)

    # access type used when enumerating ranges
    # access = 'rw-'

    runner = FridaRunner()
    session = runner.get_session()

    # grab the (size) bytes starting at the (base_address)
    dump = session.read_bytes(int(base_address, 16), int(memory_size))

    # append the results to the destination file
    with open(destination, 'ab') as f:
        f.write(dump)

    click.secho('Memory dumped to file: {0}'.format(destination), fg='green')


def list_modules(args: list = None) -> None:
    """
        List modules loaded in the current process.

        :param args:
        :return:
    """

    hook = generic_hook('memory/list-modules')
    runner = FridaRunner(hook=hook)
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to list loaded modules in current process with error: {0}'.format(response.error_reason))
        return

    data = []
    for m in response.modules:
        data.append(
            [m['name'], m['base'], str(m['size']) + ' (' + sizeof_fmt(m['size']) + ')', pretty_concat(m['path'])])

    click.secho(tabulate(data, headers=['Name', 'Base', 'Size', 'Path']))


def dump_exports(args: list) -> None:
    """
        Dumps the exported methods from a loaded module to screen.

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) <= 0:
        click.secho('Usage: memory list exports <module name>', bold=True)
        return

    module_to_list = args[0]

    runner = FridaRunner()
    runner.set_hook_with_data(
        generic_hook('memory/list-exports'), module=module_to_list)
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to list loaded modules in current process with error: {0}'.format(response.error_reason))
        return

    data = []
    for x in response.exports:
        data.append([x['type'], x['name'], x['address']])

    click.secho(tabulate(data, headers=['Type', 'Name', 'Address']))


def find_pattern(args: list) -> None:
    """
        Searches the current processes accessible memory for a specific pattern.

        :param args:
        :return:
    """

    if len(clean_argument_flags(args)) <= 0:
        click.secho('Usage: memory search "<pattern eg: 41 41 41 ?? 41>" (--string)', bold=True)
        return

    # if we got a string as input, convert it to hex
    if _is_string_input(args):
        pattern = ' '.join(hex(ord(x))[2:] for x in args[0])
    else:
        pattern = args[0]

    click.secho('Searching for: {0}'.format(pattern), dim=True)

    runner = FridaRunner()
    runner.set_hook_with_data(generic_hook('memory/search'), pattern=pattern)
    runner.run()

    response = runner.get_last_message()

    if not response.is_successful():
        click.secho('Failed to search the current process with error: {0}'.format(response.error_reason))
        return

    data = response.data

    if data and len(data) > 0:
        click.secho('Pattern matched at {0} addresses'.format(len(data)), fg='green')
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

    # TODO: Fix this method up to be python3 compatible

    if _is_string_input(args):
        pattern = ' '.join(x.encode('hex') for x in args[0])

    # create a byte array we will eval in the template
    pattern = '[{0}]'.format(','.join(['0x%02x' % int(x, 16) for x in pattern.split(' ')]))
    click.secho('Writing byte array: {0} to {1}'.format(pattern, destination), dim=True)

    runner = FridaRunner()
    runner.set_hook_with_data(
        generic_hook('memory/write'),
        destination=destination, pattern=pattern)

    runner.run()
