import sys
import re
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


def normalize_table_whitespace(text: str) -> str:
    """
    Normalize whitespace in table output to be tolerant of spacing variations
    across different terminals, OS configurations, and tabulate versions.
    
    Converts multiple spaces between columns to single spaces to allow for
    flexibility in table formatting while preserving the actual data.
    """
    lines = text.split('\n')
    normalized_lines = []
    
    for line in lines:
        # Replace multiple spaces (2 or more) with a single space
        normalized_line = re.sub(r' {2,}', ' ', line)

        # Collapse varying hyphen lengths in separator rows (e.g. -----)
        stripped = normalized_line.replace(' ', '').replace('|', '').strip()
        if stripped and all(char == '-' for char in stripped):
            normalized_line = re.sub(r'-{2,}', '-', normalized_line)

        normalized_line = normalized_line.strip()
        normalized_lines.append(normalized_line)
    
    return '\n'.join(normalized_lines)