"""
sources/_jsonl.py
-----------------
Reads the newest lines of a JSONL log without loading the whole file. The
dashboard refreshes every few seconds and the module logs grow for as long as
they run, so reading from the end keeps each refresh cheap on the Pi.
"""

import json
import os


def read_tail(path, limit, fields=None, chunk=64 * 1024):
    """Returns up to `limit` records from the end of `path`, oldest first.

    `fields`, if given, is an allow-list: every other key is dropped as the
    line is parsed, so excluded data (e.g. patient identity) never reaches
    the dashboard. Malformed lines -- including a final line the writer is
    still appending -- are skipped. A missing or unreadable file yields [].
    """
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            pos = fh.tell()
            data = b""
            # Read backwards until there are more newlines than lines wanted,
            # so the partial line at the cut is never among those returned.
            while pos > 0 and data.count(b"\n") <= limit:
                step = min(chunk, pos)
                pos -= step
                fh.seek(pos)
                data = fh.read(step) + data
    except OSError:
        return []

    records = []
    for line in data.splitlines()[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        if fields is not None:
            record = {key: record[key] for key in fields if key in record}
        records.append(record)
    return records
