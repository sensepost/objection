from setuptools import setup

from objection.__init__ import __version__

setup(
    name='objection',
    description='Instrumented Mobile Pentest Framework',
    author='Leon Jacobs',
    author_email='leon@sensepost.com',
    url='https://github.com/sensepost/objection',
    download_url='https://github.com/objection/tarball/' + __version__,
    keywords=['mobile', 'instrumentation', 'pentest', 'frida', 'hook'],
    version=__version__,
    packages=[
        'objection',
        'objection.commands',
        'objection.console',
        'objection.utils',
    ],
    include_package_data=True,
    install_requires=[
        'frida',
        'prompt_toolkit',
        'click',
        'jinja2',
        'tabulate',
        'delegator.py',
        'requests',
    ],
    entry_points={
        'console_scripts': [
            'objection=objection.console.cli:cli',
        ],
    },
)
