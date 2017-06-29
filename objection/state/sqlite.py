import atexit
import os
import tempfile

import click


class SqliteManagerState(object):
    def __init__(self):
        self.file = None
        self.temp_file = None
        self.full_remote_file = None

        # cleanup temp files when we are done with this class
        atexit.register(self.cleanup)

    def is_connected(self):
        return self.file is not None and self.temp_file is not None

    def get_cache_dir(self):

        if self.temp_file:
            return self.temp_file

        _, d = tempfile.mkstemp('objection.sqlite')
        self.temp_file = d

        return d

    def cleanup(self):
        if self.is_connected():
            click.secho('[sqlite manager] Removing cached copy of SQLite database: {0} at {1}'.format(self.file,
                                                                                                      self.temp_file),
                        dim=True)
            os.remove(self.temp_file)

            self.file = None
            self.temp_file = None
            self.full_remote_file = None

    def __repr__(self):
        return '<File:{0} LocalTemp:{1}>'.format(self.file, self.temp_file)


sqlite_manager_state = SqliteManagerState()
