"""CLI: python -m keyturn run|page ..."""

import json
import os
import sys

from .engine import Engine, KeyturnError, dump_state, page_view

USAGE = (
    "usage:\n"
    "  python -m keyturn run  <timeline> <keys_dir> <state_file> <data_dir> <out_file>\n"
    "  python -m keyturn page <state_file> <time> <page_json>\n"
)


def _cmd_run(argv):
    timeline, keys_dir, state_path, data_dir, out_path = argv
    engine = Engine(keys_dir, state_path, data_dir)
    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    count = 0
    with open(timeline, "r", encoding="ascii") as src, \
            open(out_path, "w", encoding="ascii", newline="\n") as out:
        for line in src:
            parts = line.split()
            if not parts:
                continue
            t, op, args = int(parts[0]), parts[1], parts[2:]
            result = engine.execute(t, op, args)
            out.write(result + "\n")
            print(result, file=sys.stderr)
            count += 1
    print("run: {} operations -> {}".format(count, out_path), file=sys.stderr)
    return 0


def _cmd_page(argv):
    state_path, t, out_path = argv[0], int(argv[1]), argv[2]
    with open(state_path, "r", encoding="ascii") as fh:
        state = json.load(fh)
    try:
        view = page_view(state, t)
    except KeyturnError as exc:
        print("ERR " + exc.code, file=sys.stderr)
        return 1
    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(out_path, "w", encoding="ascii", newline="\n") as fh:
        fh.write(dump_state(view))
    print("page: t={} -> {}".format(t, out_path), file=sys.stderr)
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        sys.stderr.write(USAGE)
        return 2
    cmd, rest = argv[0], argv[1:]
    try:
        if cmd == "run" and len(rest) == 5:
            return _cmd_run(rest)
        if cmd == "page" and len(rest) == 3:
            return _cmd_page(rest)
    except (OSError, ValueError, KeyError) as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 1
    sys.stderr.write(USAGE)
    return 2


if __name__ == "__main__":
    sys.exit(main())
