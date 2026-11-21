# 离线档案清单：稀疏 Merkle 批证明、双版本核验与多进程发布账本

纯离线实现，Windows 原生 Python 3.12，仅用标准库与 CPU。所有夹具均为本地虚构数据。

* 键空间固定深度二进制串（1–128 位），值可为 UTF-8 字符串**或缺席**。
* 叶哈希 `SHA256(0x00 ‖ BE32(len) ‖ utf8)`，缺席叶 `SHA256(0x02)`，
  父节点 `SHA256(0x01 ‖ 左32字节 ‖ 右32字节)`。
* 证明是**诱导树**：被审叶 + 诱导树边界上的旁枝摘要。恢复只走
  `O(键数 × 深度)` 个节点，永不展开整棵树（0 层与 128 层同样处理）。
* 双根证明里同一旁枝摘要**被前后两版共享**——这正是"一次证明复原两个根"、
  也是"未声明键变更必然导致双根核对失败"的原因。

---

## 1. 运行方式

```bash
python -m solution <command> CASE.json [--db DB.sqlite]
```

* 结果写入 stdout，UTF-8 JSON，键顺序固定，同一逻辑输入结果完全一致。
* 结构错误：退出码 `2`，输出 `{"ok": false, "error": {"code", "field", "detail"}}`；
  `field` 是出错字段的 JSON 路径（如 `proof.citations[3].hash`、`chain[1].old_root`）。
  意外内部错误退出码 `1`。
* 无参数命令：`verify`、`merge`、`proof-rebase`、`split-verify`。
* 需要 `--db` 的命令：`ledger-ingest`、`ledger-plan`、`ledger-publish`、
  `ledger-view`、`ledger-revoke`、`ledger-status`。

测试：

```bash
python -m unittest discover -s tests -v
```

可直接运行的样例见 `examples/`（见 §8）。

---

## 2. 哈希与规范化

| 项 | 定义 |
| --- | --- |
| 叶 | `sha256(0x00 ‖ uint32be(utf8 字节数) ‖ utf8)` |
| 缺席叶 | `sha256(0x02)`，**注意空串 `""` 的叶哈希与它不同** |
| 父节点 | `sha256(0x01 ‖ 左原始 32 字节 ‖ 右原始 32 字节)` |
| 空子树 | 高度 `h` 的全缺席子树哈希，`h=0` 时就是缺席叶 |

摘要一律小写十六进制；输入接受 `sha256:<64hex>` 或裸 64 hex，输出统一为
`sha256:<64hex>`。旁枝摘要可写 `"empty"`，等价于该高度的规范空子树——因为
空子树与被审的缺席叶在数值上相同，根计算无需区分两者。

旁枝按**二进制前缀字典序**输出（短前缀在其扩展之前）。

---

## 3. `verify` — 双根批证明

### 输入

```json
{
  "old_root": "sha256:…",          // 必填，可信登记中的旧根
  "new_root": "sha256:…",          // 必填，可信登记中的新根
  "policy": {                      // 可选
    "allowed_prefixes": ["0001", "11"],
    "allow_insert": true, "allow_delete": true, "allow_update": true
  },
  "declared": [                    // 可选；给出时必须恰好覆盖被审键
    {"key": "00010", "kind": "update"}
  ],
  "proof": {
    "leaves": [
      {"key": "00010", "old_value": "a", "new_value": "b"},
      {"key": "01100", "old_value": null, "new_value": "x"}
    ],
    "citations": [
      {"prefix": "0000", "hash": "empty"},
      {"prefix": "00011", "hash": "sha256:…"}
    ]
  }
}
```

规则：

1. 所有 `leaves[].key` 等深；`citations[].prefix` 长度即其高度，不得重复。
2. 旁枝前缀必须**恰好**是"被审叶诱导树"的边界：不得重复、不得父子重叠、
   不得覆盖被审叶、不得多余、不得缺失。
3. 用同一组共享旁枝分别复原 `old_root` 与 `new_root`，任一不匹配即拒绝
   （`ROOT_MISMATCH`）。因此若证明之外还有键发生变化，双根核对必然失败。
4. 每个键按 `null→值`/`值→null`/值变化分类为 `insert`/`delete`/`update`/
   `unchanged`，再按 `policy` 检查方向与允许前缀。
5. 提供 `declared` 时，其键集必须与被审键集完全一致，且声明方向必须与实测一致。

### 输出（节选）

```json
{
  "ok": true, "command": "verify", "verified": true,
  "old_root": "sha256:…", "new_root": "sha256:…",
  "depth": 5, "audited": 2, "changed": 1,
  "counts": {"insert": 0, "delete": 0, "update": 1, "unchanged": 1},
  "keys": [{"key": "00010", "old": "a", "new": "b", "kind": "update"}],
  "citations": [{"prefix": "0000", "hash": "empty"}],
  "policy": {…},
  "checks": {…}
}
```

---

## 4. `merge` — 合并同一根对的两个证明

### 输入

```json
{
  "old_root": "sha256:…", "new_root": "sha256:…",
  "policy": {…},                       // 可选，对各输入分别校验
  "proofs": [<proof>, <proof>, …]      // 至少两个，各自必须独立可验证
}
```

合并语义：

* 先**分别独立验证**每个输入（根、旁枝形状、政策）。
* 取并集：重叠叶必须一致（`LEAF_CONFLICT`），重叠旁枝摘要必须一致
  （`CITE_CONFLICT`）。
* 一个证明的旁枝若被另一个证明展开：展开后重算的子树摘要必须等于旁枝摘要，
  否则 `EXPANSION_MISMATCH`。双根共享的旁枝要求两侧展开结果都等于该摘要。
* 合并结果对受审键并集是**唯一最简**证明：旁枝集合恰等于并集诱导树边界，
  且已剔除多余旁枝（`NOT_MINIMAL` 若内部一致性检查不成立）。
* 合并**不改变**可信根与政策，结果再次按两个可信根复核，并检验合并与输入顺序无关。

### 输出

```json
{
  "ok": true, "command": "merge", "verified": true,
  "old_root": "sha256:…", "new_root": "sha256:…", "depth": 5,
  "inputs": [{"audited": 2, "citations": 5, "counts": {…}}],
  "merged": {"audited": 3, "citations": 7, "citations_before": 10, "counts": {…}},
  "keys": [{"key": "…", "old": …, "new": …, "kind": "…"}],
  "proof": {"leaves": […], "citations": […]},
  "checks": {…}
}
```

---

## 5. `proof-rebase` — 把库存证明投影到最终根

库存方持有旧根 `A` 上对固定键集 `S` 的**普通单根**最简证明；审核方只提供
`A → B → C` 任意长度**双根**变更链，每跳可能修改不同键集 `T`。

### 输入

```json
{
  "inventory": {"root": "sha256:…", "proof": {"leaves": [{"key": "…", "value": "…"}],
                                             "citations": […]}},
  "s_keys": ["000100", "010000"],     // 可选；给出时必须与库存证明键集一致
  "chain": [
    {"version": 1, "old_root": "sha256:…", "new_root": "sha256:…",
     "policy": {"allowed_prefixes": ["0", "1"]},
     "proof": {"leaves": [{"key": "…", "old_value": …, "new_value": …}],
               "citations": […]}}
  ]
}
```

处理顺序：

1. **先独立校验链的形状**：跳序、根连续性、版本严格递增；任一不满足即
   `CHAIN_BROKEN` / `VERSION_ORDER`，此时**不输出**最终证明。
2. 每一跳按自己的根对与政策独立验证（不完整或不符政策即拒绝）。
3. 只替换 `S` 中受 `T` 影响的旁枝：
   * 跳里出现 `S` 键 → 用其新值，并**独立核对**旧值哈希是否与已携带证据一致
     （`OLD_VALUE_CONFLICT`）；
   * 跳里某旁枝严格覆盖 `S` 键 → 该区域在两版间共享，键不变，**绝不**下推
     推断旁枝内容；
   * 跳里某旁枝前缀等于 `S` 边界前缀 → 其摘要必须与已携带摘要一致
     （`OLD_BRANCH_CONFLICT`，两份证据各自核对）；
   * 跳里既无叶也无旁枝覆盖的 `S` 边界 → 由该跳证明重算，替换为新侧摘要。
4. 每跳结束后，用"`S` 叶 + `S` 边界摘要"重新复原该跳新根；不匹配即说明替换越界。
5. 最终重建 `S` 的最简普通证明，并用它反向验证最终根。

### 输出

```json
{
  "ok": true, "command": "proof-rebase", "verified": true,
  "inventory_root": "sha256:…", "final_root": "sha256:…", "depth": 6,
  "hops": [{"hop": 1, "version": 1, "old_root": "…", "new_root": "…",
            "audited": 2, "modified": 2, "s_changed": ["000100"]}],
  "audited": 3, "audited_changed": 2, "disclosed_keys": 4,
  "untouched": ["100000"],
  "keys": [{"key": "000100", "value": "a", "initial": "a",
            "changes": [{"hop": 1, "from": "a", "to": "A"},
                        {"hop": 3, "from": "A", "to": "a"}],
            "first_change_hop": 1, "last_change_hop": 3, "changed": true}],
  "proof": {"leaves": […], "citations": […]},
  "checks": {…}
}
```

`first_change_hop` / `last_change_hop` 记录**真实值变化**的首尾跳次；即使值回到
旧摘要，历史变化仍保留（`changes` 完整列出）。

---

## 6. `split-verify` — 乱序分片重组证据

同一跳的证据可从多个乱序输入文件到达：

```json
{
  "old_root": "sha256:…", "new_root": "sha256:…",
  "proof": {"leaves": […], "citations": [… 完整证据 …]},   // 作为形状/覆盖基准
  "shards": [
    {"shard_id": "b", "old_root": "sha256:…", "new_root": "sha256:…",
     "citations": [{"prefix": "010", "hash": "empty"}]},
    {"shard_id": "a", "citations": [{"prefix": "0111", "hash": "sha256:…"}]}
  ]
}
```

* 每份分片先独立校验形状（前缀可解析、分片内不重复、分片内不嵌套）与其
  **已绑定根对**（`SHARD_ROOT_MISMATCH`）。
* 分片顺序无关；同一前缀重复出现必须摘要一致，否则 `SHARD_CONFLICT`。
* 额外前缀 `EXTRA_SHARD_PREFIX`、缺失前缀 `MISSING_SHARD`，均报**第一处**
  无法核对的前缀。
* **只有证据全集组装完成之后**才复原根；此前不做任何根计算。

输出含 `shards`（每片引用数）、`evidence`（引用数、共享片数、`assembled`）、`checks`。

---

## 7. 发布账本（SQLite）

### 7.1 概念

* **检查点**：身份是 `checkpoint_id`，根只是内容。回滚到完全相同的根会创建
  **新**检查点；`cp-A` 与 `cp-A-copy` 即使根相同也是两个节点。
* **跳转边**：绑定起止检查点、目标归档用途 `archive_use`、双根证明、保持不变的
  旁枝 `kept_branches`、允许变化的前缀政策、登记代次 `generation`。
  边按代次递增登记，构成 DAG。
* **审查票**：绑定边、前后根、政策版本、一个敏感类别、审查主体及其机构、
  逻辑有效期 `[issued_at, expires_at)`。
* **别名**：`aliases` 把同一人的多个 ID 折叠为同一审查主体。
* **机构**：`institutions` 登记主体所属机构，票声明机构必须与登记一致。

### 7.2 `ledger-ingest` — 两个摄取通道

```json
{
  "checkpoints": [{"checkpoint_id": "cp-A", "root": "sha256:…", "generation": 10,
                   "policy_version": 1, "label": ""}],
  "edges": [
    {"edge_id": "e1", "from": "cp-A", "to": "cp-B", "generation": 11,
     "policy_version": 1, "archive_use": "cold-archive",
     "policy": {"allowed_prefixes": ["0", "1"]},
     "kept_branches": ["0000", "001"],
     "proof": {"leaves": […], "citations": […]}},
    {"edge_id": "e2", "from": "cp-B", "to": "cp-C", "generation": 12,
     "policy_version": 1, "expected_fragments": 2,
     "fragment_id": "f1", "fragment": {"leaves": […], "citations": […]}}
  ],
  "votes": [{"vote_id": "v1", "edge_id": "e1", "category": "privacy",
             "reviewer_id": "alice", "institution_id": "inst-1",
             "policy_version": 1, "old_root": "sha256:…", "new_root": "sha256:…",
             "issued_at": 0, "expires_at": 1000}],
  "revocations": [{"vote_id": "v2", "reason": "recused"}],
  "aliases": [{"alias": "alice-work", "subject": "alice"}],
  "institutions": [{"subject": "alice", "institution_id": "inst-1"}]
}
```

关键性质：

* **幂等**：同一 `edge_id` / `vote_id` / `checkpoint_id` 重复提交保持一致结果；
  检查点内容冲突报 `CHECKPOINT_CONTENT_CONFLICT`。
* **分片暂存**：`expected_fragments > 1` 时，未收齐的边只进入 `staged`，
  **永远不会**被查询为已校验边，也不能为计划贡献根；收齐后组装的证明必须复原
  绑定的前后根，否则 `ROOT_MISMATCH`。分片互相矛盾 → `FRAGMENT_CONFLICT`。
* **单事务**：整批摄取在一个 `BEGIN IMMEDIATE` 里提交。进程在提交前被杀，
  数据库要么是旧状态，要么没有本次任何痕迹——不存在"半条边"。
* 边登记代次必须大于起始检查点代次，否则 `GENERATION_ORDER`。
* 票声明机构与登记机构不符 → `INSTITUTION_MISMATCH`。

输出逐通道列出 `accepted / verified / staged / rejected`，被拒项带 `code`/`field`/`detail`。

### 7.3 `ledger-plan` — 全局路径 × 票联合选择

```json
{
  "start_checkpoint": "cp-A", "end_checkpoint": "cp-C",
  "policy_version": 1, "logical_clock": 10,
  "archive_use": "cold-archive",              // 可选
  "s_keys": ["000100", "100000"],
  "inventory": {"root": "sha256:…", "proof": {"leaves": […], "citations": […]}}
}
```

约束：

* 起点必须是库存证明所绑定的根；终点必须已登记。
* 只使用：`policy_version` 相同、`archive_use` 匹配、两端检查点均已登记的**已校验**边。
* 每跳每个敏感类别需**两套**独立签票：绑定该边、前后根、政策版本、该类别，
  且在 `logical_clock` 的有效期内。
* **整个请求内**同一票、同一审查主体（别名折叠后）最多一次；同槽两票机构必须不同。
  已撤销或已被账本消费的票不可用。
* 目标函数（字典序）：① 全部跳中**被披露的不同键**数量 → ② 跳数 → ③ 边 ID 序列 →
  ④ `(跳次, 类别, 票 ID)` 排序后的票列表。

搜索是**联合**的：标签为 `(检查点, 已用票, 已用主体, 已披露键, 路径)`；仅当同一
检查点上另一标签在每个目标上都不劣且剩余票/主体不少于它时才剪枝。因此
"逐跳最优 → 全局最优"的假设被明确拒绝；到达同一检查点但消耗票集不同的状态
**不合并**。

输出含 `plan.edge_ids`、每跳 `votes`（含 `subject`，已折叠别名）、`disclosed_key_list`、
`fragments_hash`（所选边分片集合哈希，可回填到 `ledger-publish`）、`final_root`、
`projection`（S 在终点的最简证明）、`keys`，以及 `search` 说明。

`ledger-publish` 的 `plan` 字段可省略——省略时发布方在事务内重新执行同一联合搜索；
给出时逐项复核（边、票、`fragments_hash` 三者都必须与已提交状态一致）。

失败原因分类：

| code | 含义 |
| --- | --- |
| `TARGET_NOT_REGISTERED` | 终点检查点未登记 |
| `STRUCTURE_BROKEN` | 起点未登记 / 政策版本下无可用边 / 结构上不可达 |
| `INSUFFICIENT_VOTES` | 结构可达，但没有任何路径存在全局无冲突的票分配 |
| `START_ROOT_MISMATCH` | 库存证明根与起点检查点不符 |
| `REBASE_FAILED` | 选中的路径无法把 S 投影到终点（防御性） |

### 7.4 `ledger-publish` — 单事务提交

```json
{
  "request_id": "pub-2026-11-22-001",
  "start_checkpoint": "cp-A", "end_checkpoint": "cp-C",
  "policy_version": 1, "logical_clock": 10,
  "s_keys": ["000100"], "inventory": {…},
  "plan": {"edge_ids": ["e1", "e2"],
           "votes": [{"hop": 1, "category": "privacy", "vote_id": "v1"}, …],
           "fragments_hash": "…"}          // 可选；给出则必须匹配
}
```

在 `BEGIN IMMEDIATE` 内依次复核：起点 = 上一回执终点且根匹配 → 边已校验/连续/
政策代次 → 所选边分片集合哈希 → 票未撤销、未消费、在有效期内、绑定正确 →
全局票/主体/机构约束 → S 可独立 rebase 到终点根。全部通过后**一次性**写入
票消费、最新根与投影证明，再提交。

* 并发争用同一张票或同一起点时，先拿到写锁并提交的一方生效，另一方看到
  `VOTE_CONSUMED` / `START_NOT_CURRENT` / `IDEMPOTENCY_CONFLICT`。
* 同 `request_id` 同内容 → 返回原回执（`idempotent: true`）；同 ID 异内容 → 拒绝。
* 提交前中断：无任何状态变化；提交后响应丢失：重发同报文拿回原回执。
* 不能用"根相同"跳过中间检查点——请求必须从上一次回执的终点继续。

### 7.5 `ledger-view` / `ledger-revoke` / `ledger-status`

```bash
python -m solution ledger-view CASE.json --db DB.sqlite     # {"commit_seq": 1} 或省略取最新
python -m solution ledger-revoke CASE.json --db DB.sqlite   # {"vote_id": "v2", "reason": "…"}
python -m solution ledger-status CASE.json --db DB.sqlite   # {} 即可
```

* `ledger-view` 按**提交号**回读历史快照（回执、计划、根、投影证明）；
  后续撤票不改变已提交历史。
* `ledger-revoke` 只影响未来使用；返回 `consumed_by` 指出该票是否已被某次发布消费。
* `ledger-status` 汇总检查点/边/票/撤销/消费数量、边的状态分布、暂存边列表与提交号。

历史 `view` 与 `publish` 的 `commit_seq` 共享同一提交计数器，可据此判断先后。

---

## 8. 样例与复现

`examples/` 下每个目录是一组可直接运行的夹具：

```bash
# 1) 双根批证明
python -m solution verify examples/verify/case.json

# 2) 两个证明合并
python -m solution merge examples/merge/case.json

# 3) 三次跳转的 rebase（同一键被覆写两次、再回到旧值）
python -m solution proof-rebase examples/proof-rebase/case.json

# 4) 乱序分片
python -m solution split-verify examples/split-verify/case.json

# 5) 完整账本流程
python -m solution ledger-ingest  examples/ledger/ingest.json  --db examples/ledger/ledger.sqlite
python -m solution ledger-plan    examples/ledger/plan.json    --db examples/ledger/ledger.sqlite
python -m solution ledger-publish examples/ledger/publish.json --db examples/ledger/ledger.sqlite
python -m solution ledger-view    examples/ledger/view.json    --db examples/ledger/ledger.sqlite
python -m solution ledger-revoke  examples/ledger/revoke.json  --db examples/ledger/ledger.sqlite
python -m solution ledger-status  examples/ledger/status.json  --db examples/ledger/ledger.sqlite
```

`examples/build_examples.py` 用**完整小树**独立重算所有摘要后生成上述夹具（包括
根），因此样例本身就是一次"小树全量计算对拍"。重新生成：

```bash
python examples/build_examples.py
python -m unittest tests.test_examples -v
```

---

## 9. 测试矩阵

`python -m unittest discover -s tests -v`（约 30 秒，含需要真实起子进程的并发用例）。

| 文件 | 覆盖 |
| --- | --- |
| `tests/test_proofs.py` | 缺席与空串不同；只变更未声明键导致双根核对失败；重复/多余/缺失/父子重叠/覆盖叶旁枝；政策方向与前缀；声明方向；深度 128 单键证明不构造全树；merge 的旁枝展开、最简性、顺序无关、重叠冲突；proof-rebase 多次覆写、S∩T=∅、回到旧摘要保留历史、嵌套旁枝部分展开、断链不产出证明、版本序、旧值双重约束；split-verify 乱序/缺失/多余/冲突/根绑定；随机小树全量对拍 |
| `tests/test_ledger.py` | 检查点身份与根内容解耦；分片暂存与提交、分片重放幂等；分片冲突；边根/代次校验；已校验边不可换内容重注册；票有效期；别名折叠；随机图与穷举 `(路径 × 票分配)` 对拍；`INSUFFICIENT_VOTES` 各成因；同根不同检查点不可跳过；旧政策证明被当前计划拒绝；同键重复披露只计一次成本；更短路径占用后跳唯一审查人被淘汰；同检查点不同票集不合并；平局决胜 |
| `tests/test_publish.py` | 提交消费票；幂等；同 ID 异内容拒绝；已消费/已撤销票；起点必须是上一回执；政策代次与分片哈希复核；别名复用与同机构拒绝；历史 view 不受撤票影响；**两个独立进程 + 可复现同步点**：发布与撤票双向抢先、提交前中断、提交后响应丢失、两个发布者争同一票 |
| `tests/test_scale.py` | 150 条边 / 30 名审查主体下快速完成；选中路径可独立 rebase；超长请求因票不足被正确分类 |
| `tests/test_cli.py` | UTF-8 输出、结果稳定性、错误码与字段位置、`--db` 缺失、非法 JSON 位置、README 流程端到端 |
| `tests/test_examples.py` | `examples/` 中的每个夹具都能跑通并包含预期断言 |

---

## 10. 实现边界

* 不构造完整树：所有恢复都按诱导树遍历，128 位深度与 4 位深度代价相同量级。
  完整树只在 `examples/build_examples.py` 与 `solution/refimpl.py`（测试对拍）中出现。
* 计划搜索状态数有上限（40 万标签）；超限报 `PLAN_BUDGET_EXCEEDED` 而不是静默截断。
* 只用标准库（`hashlib`、`json`、`sqlite3`、`argparse`、`unittest` 等）与 CPU。
* 所有摘要计算在进程内完成，不依赖网络、时钟或随机数（除测试夹具生成外）；
  测试中的同步点由环境变量 `SOLUTION_SYNC_DIR` 控制，未设置时完全无副作用。
* SQLite 使用 WAL + `synchronous=FULL` + `BEGIN IMMEDIATE`；并发正确性依赖
  数据库锁，而非进程内状态。
