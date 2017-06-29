import logging
import os
from logging.config import dictConfig

import click

logging_config = dict(
    version=1,
    formatters={
        'f': {
            'format':
                '%(asctime)s %(levelname)-8s\n%(message)s\n'
        }
    },
    handlers={
        'h': {
            'class': 'logging.FileHandler',
            'formatter': 'f',
            'filename': os.path.expanduser('~/.objection/objection.log'),
            # 'maxBytes': 1000000 * 10,
            'level': logging.DEBUG
        }
    },
    root={
        'handlers': ['h'],
        'level': logging.DEBUG,
    },
)

dictConfig(logging_config)

# monkey patch secho to log to file
real_secho = click.secho


def new_secho(text, **kwargs):
    logging.info(text)
    real_secho(text, **kwargs)


click.secho = new_secho
