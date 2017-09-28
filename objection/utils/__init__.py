import logging
import os
from multiprocessing import Pool

import click

from .update_checker import check_version


class MakeFileHandler(logging.FileHandler):
    """
        Wrapper Class around the builtin Filehandler.
    """

    def __init__(self, filename: str, mode: str = 'a', encoding: str = None, delay: bool = False) -> None:
        """
            The original FileHandler's init is called, right after the
            directory used to store the objection logfile is created.

            :param filename:
            :param mode:
            :param encoding:
            :param delay:
        """

        os.makedirs(os.path.dirname(filename), exist_ok=True)
        logging.FileHandler.__init__(self, filename, mode, encoding, delay)


def new_secho(text: str, **kwargs) -> None:
    """
        Patch the secho method from the click package so that
        the text that should be echoed is logged first.

        :param text:
        :param kwargs:
        :return:
    """

    logging.info(text)
    real_secho(text, **kwargs)


# Configure the logging used in objection
logger = logging.getLogger()
handler = MakeFileHandler(os.path.expanduser('~/.objection/objection.log'))
formatter = logging.Formatter('%(asctime)s %(levelname)-8s\n%(message)s\n')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

# monkey patch secho to log to file
real_secho = click.secho
click.secho = new_secho

# kick off a background process to check the version of objection
Pool(processes=1).apply_async(check_version)
