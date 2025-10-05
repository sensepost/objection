import click

from objection.state.connection import state_connection


def _get_flag_value(args: list, flag: str) -> str:
    """
        Returns the value for a flag.

        :param args:
        :param flag:
        :return:
    """

    return args[args.index(flag) + 1] if flag in args else None


def get(args: list = None) -> None:
    """
        Gets all of the values stored in NSUserDefaults and prints
        them to screen.

        :param args:
        :return:
    """

    api = state_connection.get_api()
    defaults = api.ios_nsuser_defaults_get()

    click.secho(defaults, bold=True)


def set(args: list = None) -> None:
    """
        Sets a value in NSUserDefaults.

        :param args:
        :return:
    """

    if not args or len(args) < 2:
        click.secho('Usage: ios nsuserdefaults set <key> <value> [--type string|int|float|bool]', fg='red')
        return

    # Get explicit type if provided
    value_type = _get_flag_value(args, '--type')

    # Remove --type and its value from args if present
    if '--type' in args:
        type_index = args.index('--type')
        args = args[:type_index] + args[type_index + 2:]

    if len(args) < 2:
        click.secho('Usage: ios nsuserdefaults set <key> <value> [--type string|int|float|bool]', fg='red')
        return

    key = args[0]
    value_str = args[1]

    # Parse value based on type
    if value_type == 'bool':
        value = value_str.lower() in ['true', '1', 'yes']
    elif value_type == 'int':
        try:
            value = int(value_str)
        except ValueError:
            click.secho(f'Invalid integer value: {value_str}', fg='red')
            return
    elif value_type == 'float':
        try:
            value = float(value_str)
        except ValueError:
            click.secho(f'Invalid float value: {value_str}', fg='red')
            return
    else:
        # Default to string, but try to auto-detect type
        if not value_type:
            if value_str.lower() in ['true', 'false']:
                value_type = 'bool'
                value = value_str.lower() == 'true'
            elif value_str.isdigit() or (value_str.startswith('-') and value_str[1:].isdigit()):
                value_type = 'int'
                value = int(value_str)
            elif '.' in value_str:
                try:
                    value = float(value_str)
                    value_type = 'float'
                except ValueError:
                    value = value_str
                    value_type = 'string'
            else:
                value = value_str
                value_type = 'string'
        else:
            value = value_str

    click.secho(f'Setting NSUserDefaults key: {key} = {value} (type: {value_type})', dim=True)

    api = state_connection.get_api()
    result = api.ios_nsuser_defaults_set(key, value, value_type)

    if result:
        click.secho(f'Successfully set {key}', fg='green')
    else:
        click.secho(f'Failed to set {key}', fg='red')
