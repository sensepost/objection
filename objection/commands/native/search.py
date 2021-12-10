import json
from typing import Optional

import click

from objection.state.connection import state_connection
from objection.utils.helpers import clean_argument_flags


def _should_dump_json(args: list) -> bool:
    return '--json' in args


def _get_flag_value(flag: str, args: list) -> Optional[str]:
    target = None
    for i in range(len(args)):
        if args[i] == flag:
            target = i + 1

    if target is None:
        return None
    elif target < len(args):
        return args[target]
    else:
        click.secho(f'Could not find specified value for {flag}', bold=True)
        return None


def _should_be_quiet(args: list) -> bool:
    return '--quiet' in args


def search(args: list) -> None:
    if len(clean_argument_flags(args)) < 1:
        click.secho('Usage: native search <pattern> '
                    '(eg: "exports:*!open")'
                    '(optional: --json $target) '
                    '(optional: --quiet) ',
                    bold=True)
    api = state_connection.get_api()
    results = api.native_search(args[0])
    results_json = {
        'meta': {
            'runtime': 'java'
        },
        'data': results
    }

    should_dump_json = _should_dump_json(args)
    should_be_quiet = _should_be_quiet(args)
    if should_dump_json:
        target_file = _get_flag_value('--json', args)
        with open(target_file, 'w') as fd:
            fd.write(json.dumps(results_json))
            click.secho(f'JSON dumped to {target_file}', bold=True)

    if not should_be_quiet:
        for entry in results:
            print(entry['name'])
    return
