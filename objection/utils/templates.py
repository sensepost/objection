from os import path

from jinja2 import Environment, PackageLoader

template_env = Environment(loader=PackageLoader('objection', 'templates'))
hook_path = path.realpath(path.abspath(path.dirname(__file__) + '/../hooks'))


def _get_name_with_js_suffix(name: str) -> str:
    """
        Ensures a string ends with .js

        :param name:
        :return:
    """

    if not name.endswith('.js'):
        return name + '.js'

    return name


def _cleanup_hook_comments(hook: list) -> list:
    """
        Clean up a hook read from disk by removing the lines
        that contain comments. Lines that start with // are
        considered comments lines. Thank you Cpt. Verbose.

        :param hook:
        :return:
    """

    return [line for line in hook if not line.strip().startswith('//')]


def generic_hook(name: str, skip_trycarch: bool = False) -> str:
    """
        Compile a hook from the 'generic' directory.

        :param name:
        :param skip_trycarch:
        :return:
    """

    name = _get_name_with_js_suffix(name)
    tmpl_path = path.join(hook_path, 'generic/' + name)

    with open(tmpl_path, 'r') as f:
        hook = f.readlines()

    hook = ''.join(_cleanup_hook_comments(hook))

    if skip_trycarch:
        return hook

    final_template = template_env.get_template('generic-base.js')
    return final_template.render(content=hook)


def ios_hook(name: str, skip_trycatch: bool = False) -> str:
    """
        Compile a hook from the 'ios' directory.

        :param name:
        :param skip_trycatch:
        :return:
    """

    name = _get_name_with_js_suffix(name)
    tmpl_path = path.join(hook_path, 'ios/' + name)

    with open(tmpl_path, 'r') as f:
        hook = f.readlines()

    hook = ''.join(_cleanup_hook_comments(hook))

    if skip_trycatch:
        return hook

    final_template = template_env.get_template('objc-base.js')
    return final_template.render(content=hook)


def android_hook(name: str = None) -> None:
    pass
