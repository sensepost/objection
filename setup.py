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
    python_requires='>=3.3',
    packages=[
        'objection',
        'objection.commands',
        'objection.commands.ios',
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
    classifiers=[
        'Operating System :: OS Independent',
        'Natural Language :: English',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: JavaScript',
    ],
    entry_points={
        'console_scripts': [
            'objection=objection.console.cli:cli',
        ],
    },
)
