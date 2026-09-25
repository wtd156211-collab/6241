"""Key lifecycle engine: versioned keys, rotation windows, retire/revoke.

All time is injected from the caller; nothing here reads the system clock.
"""

import copy
import hashlib
import json
import os

SCHEMA = 1

ACTIVE = "active"
RETIRED = "retired"
REVOKED = "revoked"


class KeyturnError(Exception):
    """Semantic error carrying one of the E_* codes from the spec."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _version_num(version):
    return int(version[1:])


def _load_key(keys_dir, version):
    path = os.path.join(keys_dir, version + ".key")
    if not os.path.isfile(path):
        raise KeyturnError("E_NO_KEY")
    with open(path, "r", encoding="ascii") as fh:
        _name, hexkey = fh.read().split()
    return bytes.fromhex(hexkey)


def _keystream(key, version, data_id, length):
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = b"|".join(
            [key, version.encode("ascii"), data_id.encode("ascii"),
             str(counter).encode("ascii")]
        )
        out += hashlib.sha256(block).digest()
        counter += 1
    return bytes(out[:length])


def _tag(key, version, data_id, ct):
    block = b"|".join(
        [key, b"tag", version.encode("ascii"), data_id.encode("ascii"), ct]
    )
    return hashlib.sha256(block).hexdigest()


def encrypt_record(key, version, data_id, plaintext):
    pt = plaintext.encode("ascii")
    ks = _keystream(key, version, data_id, len(pt))
    ct = bytes(a ^ b for a, b in zip(pt, ks))
    return {"version": version, "ct": ct.hex(),
            "tag": _tag(key, version, data_id, ct)}


def decrypt_record(key, data_id, record):
    version = record["version"]
    ct = bytes.fromhex(record["ct"])
    if _tag(key, version, data_id, ct) != record["tag"]:
        raise KeyturnError("E_DECRYPT")
    ks = _keystream(key, version, data_id, len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks)).decode("ascii")


def settle(state, t):
    """Retire active versions whose window closed at or before t."""
    for entry in state["versions"]:
        if (entry["state"] == ACTIVE and entry["until"] is not None
                and t >= entry["until"]):
            entry["state"] = RETIRED
            entry["retired_at"] = entry["until"]


def page_view(state, t):
    """State as observed at t; does not mutate or persist anything."""
    now = state.get("now")
    if now is not None and t < now:
        raise KeyturnError("E_ARG")
    view = copy.deepcopy(state)
    settle(view, t)
    view["now"] = t
    return view


def dump_state(state):
    return json.dumps(state, sort_keys=True, indent=2) + "\n"


class Engine:
    def __init__(self, keys_dir, state_path, data_dir):
        self.keys_dir = keys_dir
        self.state_path = state_path
        self.data_dir = data_dir
        self._keys = {}
        if os.path.isfile(state_path):
            with open(state_path, "r", encoding="ascii") as fh:
                self.state = json.load(fh)
        else:
            self.state = {"schema": SCHEMA, "now": None,
                          "current": None, "versions": []}

    def _entry(self, version):
        for entry in self.state["versions"]:
            if entry["version"] == version:
                return entry
        return None

    def _key(self, version):
        if version not in self._keys:
            self._keys[version] = _load_key(self.keys_dir, version)
        return self._keys[version]

    def save(self):
        self.state["versions"].sort(key=lambda e: e["version"])
        directory = os.path.dirname(self.state_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(self.state_path, "w", encoding="ascii", newline="\n") as fh:
            fh.write(dump_state(self.state))

    def execute(self, t, op, args):
        settle(self.state, t)
        self.state["now"] = t
        try:
            fields = self._apply(t, op, args)
            line = "{} {} OK".format(t, op)
            if fields:
                line += " " + " ".join(fields)
        except KeyturnError as exc:
            line = "{} {} ERR {}".format(t, op, exc.code)
        self.save()
        return line

    def _apply(self, t, op, args):
        handler = getattr(self, "_op_" + op.lower(), None)
        if handler is None:
            raise KeyturnError("E_ARG")
        return handler(t, args)

    def _op_init(self, t, args):
        version = args[0]
        if self._entry(version) is not None:
            raise KeyturnError("E_VERSION_DUP")
        self._key(version)
        if self.state["versions"]:
            raise KeyturnError("E_STATE")
        self.state["versions"].append({
            "version": version, "state": ACTIVE, "from": t,
            "until": None, "retired_at": None, "revoked_at": None,
        })
        self.state["current"] = version
        return [version]

    def _op_rotate(self, t, args):
        version, window = args[0], int(args[1])
        if window < 0:
            raise KeyturnError("E_ARG")
        if self._entry(version) is not None:
            raise KeyturnError("E_VERSION_DUP")
        if self.state["versions"]:
            top = max(_version_num(e["version"])
                      for e in self.state["versions"])
            if _version_num(version) <= top:
                raise KeyturnError("E_VERSION_ORDER")
        self._key(version)
        current = self.state["current"]
        if current is not None:
            self._entry(current)["until"] = t + window
        self.state["versions"].append({
            "version": version, "state": ACTIVE, "from": t,
            "until": None, "retired_at": None, "revoked_at": None,
        })
        self.state["current"] = version
        settle(self.state, t)  # window 0 retires the old current at once
        return [version]

    def _op_retire(self, t, args):
        version = args[0]
        entry = self._entry(version)
        if entry is None:
            raise KeyturnError("E_NO_VERSION")
        if entry["state"] != ACTIVE or self.state["current"] == version:
            raise KeyturnError("E_STATE")
        entry["state"] = RETIRED
        entry["until"] = t
        entry["retired_at"] = t
        return [version]

    def _op_revoke(self, t, args):
        version = args[0]
        entry = self._entry(version)
        if entry is None:
            raise KeyturnError("E_NO_VERSION")
        if entry["state"] == REVOKED:
            raise KeyturnError("E_STATE")
        entry["state"] = REVOKED
        entry["revoked_at"] = t
        if self.state["current"] == version:
            self.state["current"] = None
        return [version]

    def _op_write(self, t, args):
        data_id, plaintext = args[0], args[1]
        current = self.state["current"]
        if current is None:
            raise KeyturnError("E_NO_CURRENT")
        record = encrypt_record(self._key(current), current, data_id, plaintext)
        os.makedirs(self.data_dir, exist_ok=True)
        path = os.path.join(self.data_dir, data_id + ".kt")
        with open(path, "w", encoding="ascii", newline="\n") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
        return [data_id, current]

    def _read_record(self, data_id):
        path = os.path.join(self.data_dir, data_id + ".kt")
        if not os.path.isfile(path):
            raise KeyturnError("E_NO_DATA")
        with open(path, "r", encoding="ascii") as fh:
            return json.load(fh)

    def _op_read(self, t, args):
        data_id = args[0]
        record = self._read_record(data_id)
        version = record["version"]
        entry = self._entry(version)
        if entry is None:
            raise KeyturnError("E_NO_VERSION")
        if entry["state"] == REVOKED:
            raise KeyturnError("E_KEY_REVOKED")
        if entry["state"] == RETIRED:
            raise KeyturnError("E_KEY_RETIRED")
        plaintext = decrypt_record(self._key(version), data_id, record)
        return [data_id, version, plaintext]

    def _op_inspect(self, t, args):
        data_id = args[0]
        record = self._read_record(data_id)
        return [data_id, record["version"]]
