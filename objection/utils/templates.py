from os import path

from jinja2 import Environment, PackageLoader

template_env = Environment(loader=PackageLoader('objection', 'templates'))
hook_path = path.realpath(path.abspath(path.dirname(__file__) + '/../hooks'))


def generic_hook(name, skip_trycarch=False):
    if not name.endswith('.js'):
        name = name + '.js'

    tmpl_path = path.join(hook_path, 'generic/' + name)

    with open(tmpl_path, 'r') as f:
        hook = f.readlines()

    hook = ''.join(hook)

    if skip_trycarch:
        return hook

    final_template = template_env.get_template('generic-base.js')
    return final_template.render(content=hook)


def ios_hook(name, skip_trycatch=False):
    if not name.endswith('.js'):
        name = name + '.js'

    tmpl_path = path.join(hook_path, 'ios/' + name)

    with open(tmpl_path, 'r') as f:
        hook = f.readlines()

    hook = ''.join(hook)

    if skip_trycatch:
        return hook

    final_template = template_env.get_template('objc-base.js')
    return final_template.render(content=hook)


def android_hook(name=None):
    pass
