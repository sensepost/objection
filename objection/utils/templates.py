from os import path

from jinja2 import Environment, PackageLoader

template_env = Environment(loader=PackageLoader('objection', 'hooks'),
                           line_statement_prefix='//jinja:',  # replaces the {% %} tokens
                           keep_trailing_newline=True)
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


def generic_hook(name: str, skip_trycarch: bool = False) -> str:
    """
        Compile a hook from the 'generic' directory.

        :param name:
        :param skip_trycarch:
        :return:
    """

    tmpl_path = path.join(hook_path, 'generic/' + _get_name_with_js_suffix(name))

    with open(tmpl_path, 'r') as f:
        hook = f.readlines()

    hook = ''.join(hook)

    if skip_trycarch:
        return hook

    final_template = template_env.get_template('base/generic-base.js')
    return final_template.render(content=hook)


def ios_hook(name: str, skip_trycatch: bool = False) -> str:
    """
        Compile a hook from the 'ios' directory.

        :param name:
        :param skip_trycatch:
        :return:
    """

    tmpl_path = path.join(hook_path, 'ios/' + _get_name_with_js_suffix(name))

    with open(tmpl_path, 'r') as f:
        hook = f.readlines()

    hook = ''.join(hook)

    if skip_trycatch:
        return hook

    final_template = template_env.get_template('base/objc-base.js')
    return final_template.render(content=hook)


def android_hook(name: str = None, skip_trycatch: bool = False) -> str:
    """
        Compile a hook from the 'android' directory.

        :param name:
        :param skip_trycatch:
        :return:
    """

    tmpl_path = path.join(hook_path, 'android/' + _get_name_with_js_suffix(name))

    with open(tmpl_path, 'r') as f:
        hook = f.readlines()

    hook = ''.join(hook)

    if skip_trycatch:
        return hook

    final_template = template_env.get_template('base/java-base.js')
    return final_template.render(content=hook)
