"""keyturn 密钥生命周期引擎：版本化密钥的轮换、作废、撤销与加解密。

口径见 README 第 2/3 节：版本区间 [from, until)，三态 active/retired/revoked，
时间全部从外部注入，不读系统时钟。
"""

import hashlib
import hmac
import json
import os

SCHEMA = 1

ACTIVE = "active"
RETIRED = "retired"
REVOKED = "revoked"

ENVELOPE_MAGIC = "KT1"


class KeyturnError(Exception):
    """语义错误，code 为 README 定义的错误码。"""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _new_version(version, t):
    return {
        "version": version,
        "state": ACTIVE,
        "from": t,
        "until": None,
        "retired_at": None,
        "revoked_at": None,
    }


def _keystream(key, n):
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(key + counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(out[:n])


def _xor(data, stream):
    return bytes(a ^ b for a, b in zip(data, stream))


def _mac(key, version, ciphertext):
    return hmac.new(
        key, b"KT1" + version.encode("ascii") + ciphertext, hashlib.sha256
    ).hexdigest()


def dump_state(obj):
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def page_view(state, t):
    """按观察时刻 t 结算页面视图，不改状态文件。"""
    versions = []
    for rec in state["versions"]:
        rec = dict(rec)
        if rec["state"] == ACTIVE and rec["until"] is not None and t >= rec["until"]:
            rec["state"] = RETIRED
            rec["retired_at"] = rec["until"]
        versions.append(rec)
    return {
        "schema": SCHEMA,
        "now": t,
        "current": state["current"],
        "versions": versions,
    }


class Engine:
    # 状态变更累积到这么多操作后落盘一次；进程结束由 finalize 兜底，
    # 避免逐操作全量写回在大规模时间线下退化成 O(n²)。
    FLUSH_INTERVAL = 500

    def __init__(self, keys_dir, state_path, data_dir):
        self.keys_dir = keys_dir
        self.state_path = state_path
        self.data_dir = data_dir
        self.keys = {}
        self.dirty = False
        self.ops_since_flush = 0
        if os.path.exists(state_path):
            with open(state_path, "r", encoding="ascii") as fh:
                state = json.load(fh)
            self.now = state["now"]
            self.current = state["current"]
            self.versions = {v["version"]: v for v in state["versions"]}
        else:
            self.now = None
            self.current = None
            self.versions = {}

    # ---- 状态落盘 ----

    def state_obj(self):
        return {
            "schema": SCHEMA,
            "now": self.now,
            "current": self.current,
            "versions": [self.versions[v] for v in sorted(self.versions)],
        }

    def save(self):
        text = dump_state(self.state_obj())
        directory = os.path.dirname(self.state_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        tmp_path = self.state_path + ".tmp"
        with open(tmp_path, "w", encoding="ascii", newline="\n") as fh:
            fh.write(text)
        os.replace(tmp_path, self.state_path)

    def finalize(self):
        self.save()
        self.dirty = False

    # ---- 操作入口 ----

    def apply(self, t, op, args):
        self.now = t
        self.settle(t)
        handler = getattr(self, "op_" + op.lower(), None)
        if handler is None:
            raise KeyturnError("E_ARG")
        try:
            return handler(t, *args)
        finally:
            self.ops_since_flush += 1
            if self.dirty and self.ops_since_flush >= self.FLUSH_INTERVAL:
                self.save()
                self.dirty = False
                self.ops_since_flush = 0

    def settle(self, t):
        """结算 t 时刻已到期的 active 版本并写回。"""
        for rec in self.versions.values():
            if rec["state"] == ACTIVE and rec["until"] is not None and t >= rec["until"]:
                rec["state"] = RETIRED
                rec["retired_at"] = rec["until"]
                self.dirty = True

    # ---- 密钥与数据文件 ----

    def _load_key(self, version):
        if version in self.keys:
            return self.keys[version]
        path = os.path.join(self.keys_dir, version + ".key")
        if not os.path.exists(path):
            raise KeyturnError("E_NO_KEY")
        with open(path, "r", encoding="ascii") as fh:
            parts = fh.read().split()
        key = bytes.fromhex(parts[1])
        self.keys[version] = key
        return key

    def _data_path(self, data_id):
        return os.path.join(self.data_dir, data_id + ".kt")

    def _read_envelope(self, data_id):
        path = self._data_path(data_id)
        if not os.path.exists(path):
            raise KeyturnError("E_NO_DATA")
        with open(path, "r", encoding="ascii") as fh:
            parts = fh.read().split()
        if len(parts) != 4 or parts[0] != ENVELOPE_MAGIC:
            raise KeyturnError("E_DECRYPT")
        return parts[1], bytes.fromhex(parts[2]), parts[3]

    # ---- 各操作，判定顺序：参数 → 版本 → 密钥文件 → 状态 → 数据 ----

    def op_init(self, t, version):
        self._load_key(version)
        if self.versions:
            raise KeyturnError("E_STATE")
        self.versions[version] = _new_version(version, t)
        self.current = version
        self.dirty = True
        return [version]

    def op_rotate(self, t, version, window_arg):
        try:
            window = int(window_arg)
        except ValueError:
            raise KeyturnError("E_ARG")
        if window < 0:
            raise KeyturnError("E_ARG")
        if version in self.versions:
            raise KeyturnError("E_VERSION_DUP")
        if self.versions and version <= max(self.versions):
            raise KeyturnError("E_VERSION_ORDER")
        self._load_key(version)
        if not self.versions:
            raise KeyturnError("E_STATE")
        previous = self.current
        self.versions[version] = _new_version(version, t)
        if previous is not None:
            old = self.versions[previous]
            old["until"] = t + window
            if t >= old["until"]:
                old["state"] = RETIRED
                old["retired_at"] = old["until"]
        self.current = version
        self.dirty = True
        return [version]

    def op_retire(self, t, version):
        rec = self.versions.get(version)
        if rec is None:
            raise KeyturnError("E_NO_VERSION")
        if rec["state"] != ACTIVE or version == self.current:
            raise KeyturnError("E_STATE")
        rec["state"] = RETIRED
        rec["until"] = t
        rec["retired_at"] = t
        self.dirty = True
        return [version]

    def op_revoke(self, t, version):
        rec = self.versions.get(version)
        if rec is None:
            raise KeyturnError("E_NO_VERSION")
        if rec["state"] == REVOKED:
            raise KeyturnError("E_STATE")
        rec["state"] = REVOKED
        rec["revoked_at"] = t
        if version == self.current:
            self.current = None
        self.dirty = True
        return [version]

    def op_write(self, t, data_id, plaintext):
        if self.current is None:
            raise KeyturnError("E_NO_CURRENT")
        version = self.current
        key = self._load_key(version)
        data = plaintext.encode("ascii")
        ciphertext = _xor(data, _keystream(key, len(data)))
        os.makedirs(self.data_dir, exist_ok=True)
        line = "{} {} {} {}\n".format(
            ENVELOPE_MAGIC, version, ciphertext.hex(), _mac(key, version, ciphertext)
        )
        with open(self._data_path(data_id), "w", encoding="ascii", newline="\n") as fh:
            fh.write(line)
        return [data_id, version]

    def op_read(self, t, data_id):
        version, ciphertext, mac = self._read_envelope(data_id)
        rec = self.versions.get(version)
        if rec is None:
            raise KeyturnError("E_NO_VERSION")
        if rec["state"] == REVOKED:
            raise KeyturnError("E_KEY_REVOKED")
        if rec["state"] == RETIRED:
            raise KeyturnError("E_KEY_RETIRED")
        key = self._load_key(version)
        if not hmac.compare_digest(mac, _mac(key, version, ciphertext)):
            raise KeyturnError("E_DECRYPT")
        plaintext = _xor(ciphertext, _keystream(key, len(ciphertext)))
        return [data_id, version, plaintext.decode("ascii")]

    def op_inspect(self, t, data_id):
        version, _, _ = self._read_envelope(data_id)
        return [data_id, version]
