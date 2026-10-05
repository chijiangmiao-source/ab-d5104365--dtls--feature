# 深空中继 · DTLS 1.3 遥测审计台

审查员用于复核深空中继转发的加密遥测捕获：确认重复捕获、过期序号或伪造的
KeyUpdate 不会被当作新的有效指令。

## 范围

- 仅接受 **无 CID 的 DTLS 1.3 统一头**（`001C SLEE`，C=0）
- 仅 **TLS_AES_128_GCM_SHA256**（SHA-256 HKDF / AES-128-GCM / 16 字节标签）
- 仅 **单方向** 记录；初始接收 epoch 与 32 字节 traffic secret 由页面提供
- 序号由原始头部截断字段恢复（RFC 9147 §4.2.2 / RFC 9000 §A.3）
- 记录密钥与 IV 按 TLS 1.3 标签派生（`HKDF-Expand-Label(secret, "key"/"iv", "")`）
- **AEAD 认证成功后才解开内部内容类型**（DTLSInnerPlaintext 去零填充）
- 每个 epoch 以 **最高序号 + 64 位位图** 裁定 新到 / 重复 / 过旧
- **合法 KeyUpdate 先经认证**，再派生下一 epoch 密钥（`"traffic upd"`）并重置窗口；
  失败、重复或旧 epoch 记录绝不推进秘密或当前窗口（旧 epoch 记录只更新其自身
  epoch 的重放状态，用于识别迟到的重放）

## 运行

```bash
docker compose up app                 # 默认宿主机端口 8080
HOST_PORT=9000 docker compose up app  # 可配置宿主机端口
```

打开 `http://localhost:8080/`：填写审计标识、初始 epoch、64 位十六进制
traffic secret，按捕获顺序粘贴至多 48 条 Base64 记录并提交；之后可用同一
审计标识重新打开冻结裁决。每条记录显示 epoch、完整序号、认证结果、重放窗口
前后状态与应用数据摘要（SHA-256）；存在违规时页面经 API 显示首个截断 / 长度 /
认证 / 状态违规的**原始偏移**（记录内字节偏移），同一审计标识再次提交会原子
替换旧裁决，旧成功证据随之清除。

## 验收（verify 容器）

```bash
docker compose up --exit-code-from verify
```

`verify` 容器随 Compose 启动（等待 app 健康检查通过），实际执行：

1. **构建检查** — 字节编译应用、导入服务模块、校验页面表单
2. **复核规则测试** — 重放窗口边界（偏移 63/64）、序号恢复、KeyUpdate
   推进纪律、伪造抵抗、RFC 5869 / AES-GCM 测试向量
3. **HTTP 冒烟** — 针对运行中的服务验证 KeyUpdate 推进与窗口重置、
   重放边界裁定、伪造 KeyUpdate 不推进秘密、截断/长度违规的原始偏移、
   以及再次提交后旧成功证据被清除

完成后容器退出，退出码即验收结果（0 = 通过，1 = 失败）。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/healthz` | 健康响应 `{"status":"ok"}` |
| `GET` | `/` | 审计页面 |
| `POST` | `/api/audit` | 提交捕获并冻结裁决（替换同标识旧裁决） |
| `GET` | `/api/audit/{audit_id}` | 重新打开冻结裁决 |
| `GET` | `/api/audit/{audit_id}/record/{index}/trace` | 追溯某条已出现记录的占位证据（取自冻结时逐记录快照） |

`POST /api/audit` 请求体：

```json
{
  "audit_id": "relay-001",
  "initial_epoch": 3,
  "traffic_secret": "64 hex chars",
  "records": ["<base64 record>", "..."]
}
```

响应即冻结裁决：`ok`、`first_violation{record_index,kind,offset,message}`、
逐记录裁定（epoch/seq/replay/auth/窗口前后/摘要/违规）与最终接收状态
（当前 epoch、推进次数、各 epoch 窗口）。

### 占位证据追溯

`GET /api/audit/{audit_id}/record/{index}/trace` 从冻结裁决中取出该记录在
**裁决当时**的占位证据，证据只来自该记录自身冻结的 `window_before` 逐记录
快照，绝不以最终窗口倒推：

- `epoch` / `seq` / `replay` / `auth`：所属 epoch、恢复后的完整序号、裁定与认证结果
- `adjudication_window{epoch,highest,bitmap,lower_bound,window_size}`：裁决时该
  epoch 的最高序号、64 位位图及窗口下界 `highest-63`
- `distance`：裁决时 `highest - seq`
- `bit_evidence{within_window,bit_offset,bit_value}`：该记录对应窗口位的占位证据
- 重复（`replay="duplicate"`）：`bit_value=1`，`originator{record_index,epoch,
  seq,auth="ok"}` 指出最先使该位有效的、已认证通过的原始记录
- 过旧（`replay="too_old"`）给出裁决时最高序号、相差值与窗口下界，
  `bit_evidence.within_window=false` 且**不返回/不伪造任何占位记录**
- 新到记录与认证失败记录返回 `traceable_placeholder=false` 与明确说明，
  表示没有可追溯的重复占位

窗口前移把旧位挤出后，重新追溯较早记录仍依据冻结快照返回原裁决（重复仍为
重复、过旧仍为过旧），不受最终窗口影响。

## 违规类型与偏移约定

| kind | 含义 | offset 指向 |
| --- | --- | --- |
| `truncation` | 记录被截断（头部字段不全、声明长度超出实际） | 解析中断/数据耗尽处 |
| `length` | 长度不一致（声明长度偏短、密文不足 16 字节标签、内部明文无类型字节） | 长度字段或密文起始 |
| `authentication` | AEAD 标签校验失败 | 标签起始（记录末尾 −16） |
| `state` | 状态违规（非统一头、含 CID、epoch 无密钥、KeyUpdate 畸形等） | 相关字段 |

## 本地开发（不用 Docker）

```bash
pip install -r requirements.txt
python -m unittest discover -s tests          # 复核规则测试
uvicorn server.main:app --port 8000           # 启动服务
APP_BASE_URL=http://127.0.0.1:8000 python verify.py   # 完整验收
```
