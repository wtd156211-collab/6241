"""命令行入口：

    python -m keyturn run  <时间线> <密钥目录> <状态文件> <数据目录> <结果文件>
    python -m keyturn page <状态文件> <时刻> <页面 JSON>
"""

import json
import os
import sys

from .engine import Engine, KeyturnError, dump_state, page_view

USAGE = (
    "usage:\n"
    "  python -m keyturn run  <timeline> <keys-dir> <state-file> <data-dir> <out-file>\n"
    "  python -m keyturn page <state-file> <time> <page-json>\n"
)


def _write_text(path, text):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="ascii", newline="\n") as fh:
        fh.write(text)


def _cmd_run(args):
    if len(args) != 5:
        sys.stderr.write(USAGE)
        return 2
    timeline, keys_dir, state_path, data_dir, out_path = args
    engine = Engine(keys_dir, state_path, data_dir)
    lines = []
    with open(timeline, "r", encoding="ascii") as fh:
        for raw in fh:
            raw = raw.rstrip("\n")
            if not raw:
                continue
            parts = raw.split(" ")
            t = int(parts[0])
            op = parts[1]
            try:
                fields = engine.apply(t, op, parts[2:])
                lines.append("{} {} OK {}".format(t, op, " ".join(fields)))
            except KeyturnError as err:
                lines.append("{} {} ERR {}".format(t, op, err.code))
    engine.finalize()
    _write_text(out_path, "\n".join(lines) + "\n" if lines else "")
    return 0


def _cmd_page(args):
    if len(args) != 3:
        sys.stderr.write(USAGE)
        return 2
    state_path, time_arg, out_path = args
    try:
        t = int(time_arg)
    except ValueError:
        sys.stderr.write("E_ARG: 观察时刻不是整数\n")
        return 2
    try:
        with open(state_path, "r", encoding="ascii") as fh:
            state = json.load(fh)
    except (OSError, ValueError) as exc:
        sys.stderr.write("E_ARG: 状态文件不可读: {}\n".format(exc))
        return 2
    if t < state["now"]:
        sys.stderr.write("E_ARG: 观察时刻 {} 早于状态时刻 {}\n".format(t, state["now"]))
        return 2
    _write_text(out_path, dump_state(page_view(state, t)))
    return 0


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        sys.stderr.write(USAGE)
        return 2
    command, rest = args[0], args[1:]
    if command == "run":
        return _cmd_run(rest)
    if command == "page":
        return _cmd_page(rest)
    sys.stderr.write(USAGE)
    return 2


if __name__ == "__main__":
    sys.exit(main())
