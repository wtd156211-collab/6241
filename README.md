# wt-033 keyturn 密钥轮换与多版本共存（从 0 实现）

起始环境没有代码：`samples/` 是密钥材料、操作序列与逐行期望结果，`web/` 空着，都要新写。

## 1. 范围

做的：密钥生命周期引擎（库 + `python -m keyturn` 入口）、轮换/作废/撤销与加解密、`web/index.html` 版本区间页面、
标准库 `unittest`（`python -m unittest discover` 覆盖 `samples/`）。

不做：口令与密码管理、密钥托管后台、密钥材料生成（`samples/keys/` 只读）；多进程/多线程；网络、数据库、落库；第三方库/
CDN/构建；页面写回状态；非法输入容错（`samples/` 保证合法）。

## 2. 口径与公式

版本号 `v` + 4 位十进制（`v0001` 起）、只增不减；**有效区间**是半开区间 `[from, until)`，`until = null` 表示还没有终点。

- 加密只用 `current`（没有报 `E_NO_CURRENT`，不许退回旧版）；解密只用数据自带的版本，`revoked`/`retired` 分别报
  `E_KEY_REVOKED`/`E_KEY_RETIRED`，`active` 才真解。
- **共存窗口**：`ROTATE <版本> <窗口秒 W>` 在 `t` 执行时，上一 `current` 的 `until = t + W`；窗口内两版都 `active`，但只有新版能加密。
- **到期**：任何操作前先结算 `时刻 >= until` 的 `active` 版本（转 `retired`、`retired_at = until`）并写回状态文件；`page` 只按
  观察时刻算、不写回（`asof.txt`）。
- **作废与撤销**：作废是常规到期或 `RETIRE` 手工提前，作废后只能 `INSPECT`；撤销是紧急处置与终态，撤销 `current` 后
  `current = null`、加密报 `E_NO_CURRENT`。
- **时间注入**：时刻只来自时间线每行首段、`page` 参数与状态文件里的 `now`，不得读系统时钟。

## 3. 状态机与状态文件

`active`/`retired`/`revoked` 三态（在用/已作废/已撤销）；窗口内的旧版仍是 `active`（能解密、不能加密），`current` 恒为某个
`active` 版本或 `null`。

- `INIT <版本>`（状态为空）：`active`、`from = 时刻`、`until = null`、`current` = 版本。
- `ROTATE <版本> <窗口秒>`（版本没出现过、大于 `current`、密钥文件在）：新版 `active`、`from = 时刻`；上一 `current` 的
  `until = 时刻 + 窗口`（窗口 0 时立刻 `retired`）；`current` = 新版。
- `RETIRE <版本>`（`active` 且不是 `current`）：转 `retired`，`until = retired_at = 时刻`。
- `REVOKE <版本>`（存在且不是 `revoked`）：转 `revoked`、`revoked_at = 时刻`；是 `current` 时 `current = null`。
- `WRITE <数据ID> <明文>`（有 `current`）：用 `current` 加密写 `<数据目录>/<数据ID>.kt`（同 id 覆盖），数据带版本。
- `READ <数据ID>`（数据文件在）：按数据自带版本套第 2 节，成功输出明文。
- `INSPECT <数据ID>`（数据文件在）：只读出数据自带版本，不看状态、不用密钥。

错误码：`E_ARG`（窗口为负）、`E_NO_KEY`、`E_VERSION_DUP`、`E_VERSION_ORDER`、`E_NO_VERSION`、`E_STATE`（状态不允许该操作）、
`E_NO_CURRENT`、`E_NO_DATA`、`E_KEY_RETIRED`、`E_KEY_REVOKED`、`E_DECRYPT`；判定顺序：参数 → 版本 → 密钥文件 → 状态 → 数据。

状态文件：`json.dumps(obj, sort_keys=True, indent=2)` + 末尾 `\n`；字段 `schema`（恒 1）、`now`（最后一次操作
时刻）、`current`、`versions`（版本号升序，每项 `version`、`state`、`from`、`until`、`retired_at`、`revoked_at`），见
`expected/overlap.state.json`。**重启**：只按状态文件与数据目录恢复，版本关系、窗口端点、作废与撤销状态都要与重启前一致
（`restart-*.txt` 分两个进程跑）。

## 4. 输入输出与文件格式

### 4.1 素材文件

密钥文件 `samples/keys/<版本>.key`：纯 ASCII、单 `\n`、一行 `<版本> <64 位小写十六进制>`；只有 `INIT`/`ROTATE` 引用过的版本才进
状态，目录里可以多出没有用到的版本。时间线 `samples/timelines/*.txt`：纯 ASCII、单 `\n`、每行 `<时刻> <OP> <参数…>`，半角空格
分隔；时刻非负、整条非递减；数据 id 与明文只含 `[A-Za-z0-9._-]`；数据写 `<数据目录>/<数据ID>.kt`，格式自定，但要带版本、要由
该版本密钥参与生成（明文不得原样出现）。

### 4.2 命令行与结果文件

```
python -m keyturn run  <时间线> <密钥目录> <状态文件> <数据目录> <结果文件>
python -m keyturn page <状态文件> <时刻> <页面 JSON>
```

在仓库根目录跑，日志走 stderr；退出码 0 表示命令跑完（语义错误只写进结果文件）。结果文件一行对一时间线一行，纯 ASCII、单
`\n`：`<时刻> <OP> OK <字段…>` 或 `<时刻> <OP> ERR <码>`；OK 字段按第 3 节，`READ` 多一段明文。

### 4.3 页面数据与页面

`page` 写出的 JSON 与状态文件同形，只是 `now` 换成观察时刻、`state`/`retired_at` 按它结算；观察时刻必须 ≥ 状态里的 `now`
（否则 `E_ARG`），且不改状态文件。

- 打开：仓库根目录 `python -m http.server 8000`，浏览器开 `http://127.0.0.1:8000/web/index.html`；只用原生 HTML/CSS/JS + 内联
  SVG，不引 CDN、不构建。
- 数据：先跑 `python -m keyturn page var/overlap/state.json 8000 web/data.json`，页面相对路径 `fetch('data.json')` 读它。
- 必现：① 每版一条横条，盖住 `[from, 终点)`（终点取 `until`，`null` 时取 `revoked_at`，再 `null` 取 `now`）；② 三态各一色 +
  图例；③ 横条起点（轮换）与撤销时间点；④ `current`；⑤ 横条按版本号自上而下、横轴为时间（秒）。

## 5. 性能与验收口径

规模：单条时间线 ≤ 2×10^4 行、版本数 ≤ 10^5、数据条目 ≤ 10^5、单条重放 ≤ 30 秒；`READ` 不许遍历 `keys/` 逐个试解，也不许
换版本兜底。

1. 环境：Python 3.13、只用标准库、无构建；`python -m unittest discover` 跑通，用例只读 `samples/`。
2. 正确性：`expected/<case>.out.txt`、`overlap`/`asof` 的 `<case>.state.json`、`*.page.json` 都与实现输出逐字节相同；重跑两次
   结果不变，没有读系统时钟的地方。
3. 轮换与撤销：轮换前后数据都能读出；`时刻 >= until` 或 `RETIRE` 后旧版报 `E_KEY_RETIRED`；撤销后立刻报 `E_KEY_REVOKED`，
   撤销 `current` 后加密报 `E_NO_CURRENT`。
4. 重启：`restart-1`、`restart-2` 分两个进程、共用状态与数据目录跑，结果与 `restart-*.out.txt` 相同。
5. 数据与页面：数据文件里搜不到明文原文；按 4.3 起服务能打开、五项必现齐全、横条起止与 `web/data.json` 一致。

## 6. 样例说明

`timelines/<case>.txt` ↔ `expected/<case>.out.txt` 一一对应，数字是操作条数：`rotate` 13（轮换、窗口内新旧互读、端点、作废后
仍能 `INSPECT`）、`asof` 4（状态文件里旧版仍 `active`、页面已 `retired`）、`retire` 11（手工提前作废、重复作废、`current` 不能
被作废）、`revoke` 17（撤销 `current` 后没有当前版本、撤销终态）、`overlap` 21（三次轮换、窗口重叠、窗口 0）、`deep` 22（四版
同时在用）、`errors` 23（空状态加密、缺数据、重复 `INIT`/版本、版本倒退、缺密钥、窗口为负）、`restart-1` 5 +
`restart-2` 10（换进程续跑，中间不清理 `var/restart/`）。页面样例见 `expected/*.page.json`，里面的 `now` 就是观察时刻。

核对 `overlap`：

```
python -m keyturn run samples/timelines/overlap.txt samples/keys var/overlap/state.json var/overlap/store var/overlap/out.txt
python -m keyturn page var/overlap/state.json 8000 var/overlap/page.json
```

结果与 `expected/overlap.*` 三个文件比（`Get-FileHash` 或 `cmp`）一致即逐字节相同。

## 7. 待补的文档

真实规模的数据要自备；密钥材料怎么取、撤销后要不要回填重加密、密文格式要不要跨版本稳定，都还没定。
