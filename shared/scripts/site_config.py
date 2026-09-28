#!/usr/bin/env python3
"""Everything that says which deployment this is, kept in one file.

Names, addresses and the contact to write to live beside the node list instead
of inside the code. A second copy of this fleet is stood up by writing that one
file, and the code can be published without publishing where it runs.

Values are read on each use. They change when a person edits them, never while
a request is in flight, so holding a copy would only create a way for two
processes to disagree about what this machine is called.
"""
import json
import sys
from pathlib import Path

SETTINGS_PATH = Path('/usr/local/etc/vpn-subscription/site.json')


def settings():
    """What this deployment calls itself, or a clear stop if nobody has said."""
    try:
        return json.loads(SETTINGS_PATH.read_text())
    except FileNotFoundError:
        raise SystemExit(f"{SETTINGS_PATH} is missing: copy site.example.json "
                         "there and fill it in")
    except json.JSONDecodeError as error:
        raise SystemExit(f"{SETTINGS_PATH} is not valid JSON: {error}")


def value(path):
    """One setting by dotted name, for the shell scripts that need a string."""
    found = settings()
    for step in path.split('.'):
        found = found[step]
    return found


if __name__ == '__main__':
    print(value(sys.argv[1]))
