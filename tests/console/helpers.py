import sys
from contextlib import contextmanager
from io import StringIO


# http://schinckel.net/2013/04/15/capture-and-test-sys.stdout-sys.stderr-in-unittest.testcase/
@contextmanager
def capture(command, *args, **kwargs):
    out, sys.stdout = sys.stdout, StringIO()

    try:

        command(*args, **kwargs)
        sys.stdout.seek(0)
        yield sys.stdout.read()

    finally:

        sys.stdout = out
