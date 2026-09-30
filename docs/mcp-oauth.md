# 私有掌心窗 MCP：OAuth 部署与验证

此分支保留 Android → Python Server ← Node MCP 的通信方式，只为 Node MCP 加上单用户 OAuth。不要在审阅和确认合并之前部署。本文件取代旧文档中的匿名 MCP、SSE 连接和 MCP `/health` 配置检查步骤。

## 安全边界

- 一个设备主人、一个预配置 ChatGPT OAuth 客户端；无公众注册、无动态客户端注册。
- OAuth 由固定版本 `oidc-provider` 实现：Authorization Code + 强制 PKCE S256、精确回调匹配、一次性 60 秒授权码、600 秒访问令牌。
- 访问令牌为组件生成的 opaque token，通过同一授权服务的状态验证有效性、到期、目标资源、客户端、主人和 `phone:control` 权限；不是固定 API key，也不是把手机 Token 包装为 OAuth。
- Refresh token 每次使用都会轮换；重放撤销对应 grant。Grant 和 refresh token 为 90 天绝对期限：从首次授权计算，轮换不延长上限，到期后需再次授权。Access token 仍为 10 分钟。
- `oidc-provider@9.12.2` 的 `expiresWithSession` 对唯一预配置客户端显式返回 false；现有 `issueRefreshToken` 配置仍负责发放刷新令牌。无需增加 `offline_access`，权限仍只有 `phone:control`。浏览器 Session 仍为 1 小时，删除或到期不会撤销 Connector 授权。首次授权仍须主人登录和明确同意；后续刷新无需主人密码。
- `/mcp` 和 `/mcp-wallet` 均需访问令牌。`/sse`、`/messages` 已停用：匿名请求 401，认证后 410。缺配置时统一 503。
- `/` 和 `/health` 公开且仅报告服务存活；`/health` 成功不代表 OAuth 或手机连接已验证。
- `LINJIAN_TOKEN` 仍只用于 MCP/手机访问 Python Server，不能登录授权页，也不能访问 MCP。
- 登录页面需要独立的高熵 `MCP_OWNER_SECRET`，有 CSRF、Origin 检查、HttpOnly/Secure cookie、限流及显式同意步骤。
- OAuth 配置密钥只保存在 Render 环境变量；不创建 `.env`，不写入代码、截图、日志或聊天。ChatGPT 的 Client Secret 字段保存独立的 OAuth 客户端密钥，这是授权连接所需的另一份受保护副本。

## Render 环境变量

现有 Python Server 的环境变量与协议不变。以下新变量仅配置在 **zhangxinchuang-mcp**，不要放进 shared 环境变量组。

| 变量 | 是否为 Secret | 如何配置 |
| --- | --- | --- |
| `MCP_OWNER_SECRET` | 是 | Blueprint 自动生成。仅你本人在授权登录页输入；至少 32 字符，不要改成短密码。 |
| `MCP_CLIENT_SECRET` | 是 | Blueprint 自动生成。仅用于 ChatGPT OAuth Client Secret 字段；不能代替主人登录。 |
| `MCP_COOKIE_SECRET` | 是 | Blueprint 自动生成；用于签名浏览器 cookie，不需要复制到 ChatGPT。 |
| `MCP_OAUTH_JWKS` | 是 | 私钥 JWK Set JSON，手动私下生成并填入；参见下方。 |
| `MCP_OAUTH_REDIRECT_URIS` | 否 | JSON 数组，恰好一个 ChatGPT 管理页给出的完整 HTTPS 回调地址，逐字符一致。 |
| `MCP_PUBLIC_URL` | 否／可选 | 默认使用 Render 自动提供的 `RENDER_EXTERNAL_URL`。仅自定义域名时设置为该 MCP 的 HTTPS 根地址，不带路径、查询或片段。 |
| `TURSO_DATABASE_URL` | 连接地址／必填 | Turso **libSQL** 数据库的 `libsql://...` 或 `https://...` 根地址；不带 Token、查询参数或路径。SDK 强制使用 HTTPS。 |
| `TURSO_AUTH_TOKEN` | 是／必填 | 仅该 OAuth 数据库的读写访问 Token，只在 Render MCP 的 Secret 字段私下填写；不要使用组织级管理 Token，不发到聊天或提交 GitHub。 |
| `NODE_VERSION` | 否 | Blueprint 固定 `24.19.0`；本地协议测试服务使用 Node SQLite，生产不使用本地 SQLite。 |
| `NODE_ENV` | 否 | Blueprint 设置为 `production`。 |

现有 `LINJIAN_URL`、`LINJIAN_TOKEN`、`LINJIAN_DEFAULT_DEVICE` 保留。三个新随机 Secret 彼此必须不同，也不能与 `LINJIAN_TOKEN` 相同。修改认证密钥或回调配置会使旧授权失效。

本版不再读取 `MCP_OAUTH_DB_PATH`，没有本地数据库兜底。Turso 配置缺失时拒绝访问，不自动创建免费或付费云资源。生产只允许 TLS 远端地址；仅 `NODE_ENV=test` 且不在 Render 时允许环回 HTTP，供自动化测试使用。不要把 Render 的 NODE_ENV 改成 test。

**签名密钥只在准备配置时由你私下生成。** 在自己的终端进入 `mcp` 后运行 `node scripts/generate-jwks.js`，将唯一一行 JSON 直接复制到 Render 的 `MCP_OAUTH_JWKS`，然后清理剪贴板和终端显示；不要发给助手、写入仓库或展示截图。该脚本使用 Node 标准密码学库，不接收网络请求。本次开发测试只生成了临时测试密钥，未生成生产密钥。

当前组件支持 issuer identification，预期稳定回调为 `https://chatgpt.com/connector_platform_oauth_redirect`。配置值格式为 `["https://chatgpt.com/connector_platform_oauth_redirect"]`。**仍以你自己的 ChatGPT MCP 管理页显示的完整地址为准**；如果显示 `/connector/oauth/具体ID`，复制该精确地址。不能使用 `*`、整个域名、任意路径或前缀匹配。

如果在创建连接前还看不到回调地址，可先用上面的稳定回调预配置；得到管理页实际地址后核对，若不同则更新 Render 变量并重启，之后再登录授权。配置缺失时服务只保留存活检查，其余请求会拒绝；不能为了完成创建而关闭认证。

## 合并获批后才执行的部署顺序

1. 你本人在 Turso 创建免费账号及一个专用于 OAuth 的 **libSQL 数据库**，优先选择靠近 Render 的区域。不要创建新 Turso 引擎数据库（其客户端不同）。生成仅这个数据库的读写访问 Token，复制地址与 Token 到 Render 的上述两个字段；不需要手工建表，第一次数据库操作会幂等创建 artifacts 表和过期索引。
2. MCP 保持 `plan: free`、单实例、无 Disk。保留所有现有 OAuth Secret、issuer 和回调，不重新生成。移除旧 `MCP_OAUTH_DB_PATH` 配置。保存环境变量/同步 Blueprint 可能触发部署，应在批准的发布窗口操作；本轮不要点部署。
3. 获批合并并发布后，在 ChatGPT 重新授权一次，开始新的 90 天授权期。旧本地 SQLite 的 Grant、Token 等记录不会迁移到新云库，因此旧凭据无法在新库验证；之后正常重启无需再迁移或重新授权。

本次任务仅提交配置，不执行上述云端操作。Blueprint 不再声明付费实例、Disk 或付费数据库。Turso 在免费额度内使用，不自动升级付费。若以前已实际开通付费资源，修改 YAML 并不等于它们已被删除或停止计费，需由你在后台单独核对；本轮不删除云资源。Turso 免费额度和政策以其当前控制台为准。

## ChatGPT 连接

- 地址：`https://你的-mcp-域名/mcp`，不要填 Python Server 地址，不要加 `?token=`。
- 认证选择 **OAuth**，使用预配置／手动客户端凭据。
- Client ID：`zhangxinchuang-chatgpt`（公开标识，不是秘密）。
- Client Secret：你在 Render 中的 **MCP_CLIENT_SECRET**，只填入 ChatGPT 的受保护配置字段，不发到聊天。
- 无需手工填写 access token，也不选择“无认证”。如果界面只有 CIMD/DCR 且不允许手动 Client ID/Secret，不要绕过认证；需先核对该账号界面能力。
- 元数据自动发现授权与 token 端点。打开授权链接后，在自己的 MCP 域名页面输入 **MCP_OWNER_SECRET**，然后明确点击“允许访问”。
- ChatGPT 自动完成 PKCE 和令牌交换，之后用 `Authorization: Bearer ...` 请求工具。
- 首次联调只运行 `linjian_status` 或 `get_phone_state`；截图、输入、点击等操作另行确认。

公开元数据：`/.well-known/oauth-protected-resource`、`/.well-known/oauth-protected-resource/mcp`、`/.well-known/oauth-authorization-server`、`/.well-known/openid-configuration`。规范资源标识为 MCP HTTPS 根地址加 `/mcp`，两个工具集合共享此资源。

## 存储、重启与撤销

OAuth 状态保存在远程 Turso/libSQL 的 artifacts 表中，包含运行时会话和令牌记录，**这是敏感运行数据，不能提交 GitHub或发到聊天**。表结构、namespace 和各 adapter 方法语义保持不变。生产使用官方 `@libsql/client@0.18.0` 的 `/http` 客户端，不使用本地 replica、syncUrl 或结果缓存。读取在 `write` batch（BEGIN IMMEDIATE）中执行，按 libSQL 语义转发主库；consume 是单条条件 UPDATE，仅 rowsAffected=1 成功，跨客户端也只能消费一次。

Render 免费实例休眠/重新部署不会清空外部数据库，但免费实例仍会在闲置后休眠并冷启动，期间请求可能超时。持久化不保证服务永远在线，也不能保证客户端自动重试。详见 [Render 免费实例限制](https://render.com/docs/free)。仍按单个 MCP 实例运行，未实现分布式表单 CSRF 或限流。

每个数据库 HTTP 请求有 5 秒超时，包含响应体读取；禁用 HTTP 重定向，不自动重试 SQL。SDK 当前 HTTP 实现也不自动重放失败操作。网络失败只返回无敏感信息的错误：工具/interaction 路由 503，provider token 路由安全返回 server_error；不得退回本地库、空授权或匿名访问。数据库恢复后新的请求可正常访问，初始化失败允许后续请求重新执行幂等建表。**消费或轮换的响应丢失时，不能保证继续使用原 refresh token**：它可能已经消费；再次使用会触发重放保护，需要重新授权。不要为提高可用性关闭重放保护或盲目重试。

Interaction/授权码保持 5 分钟/60 秒有效期，均通过远程表保存。表单 CSRF nonce 故意仍只保存在进程内存：重启后旧表单安全失败，并提示关闭页面、返回 ChatGPT 重新发起授权。失效 Interaction、缺失或不匹配的 cookie/路径也给出同一提示；不自动构造新的授权 URL，不绕过 Origin/CSRF，不回显异常或凭据。已完成授权的 refresh token 不依赖这个 Map。

正常重新部署必须保持数据库和配置密钥不变。主动撤销、90 天期限届满、检测到令牌重放，或 issuer/owner secret/cookie secret/client secret/JWKS/回调配置变化会要求重新授权。后者沿用原有命名空间隔离策略。不要通过恢复旧数据库快照撤销已发生的 revoke/rotation；灾难恢复需使旧授权失效后重新授权。数据库包含敏感令牌，不能提交 GitHub、下载到聊天或记录到日志。

泄漏时轮换 Render 的对应 Secret 并重启（配置命名空间变化会使既有授权全部失效），然后在 ChatGPT 重新授权。还支持标准 `/token/revocation` 撤销；不提供未认证的管理 API。

数据库 Token 是数据库访问凭据，与 MCP_CLIENT_SECRET/LINJIAN_TOKEN 不同，不参与 OAuth namespace；正常轮换数据库 Token 而保留同一数据库不撤销已有 OAuth 授权。应记录数据库 Token 的有效期并在到期前更新。若数据库 Token 泄漏，需撤销泄漏的 Token，并主动使 OAuth 旧授权失效后重新授权。

## 本地验证

在 `mcp/` 安装锁定依赖后运行 `pnpm test`（等价 `node --test test/*.test.js`）。测试在本机环回地址运行 Hrana v2 HTTP 协议子集测试服务，底层使用真实 SQLite 执行 SQL；OAuth 端使用真实官方 SDK 通过 HTTP 访问它，真实 server.js 子进程重启而测试数据库服务保持运行。所有凭据均临时生成，只使用本地服务，不控制手机，不访问生产 Turso。临时数据库结束后删除。测试服务不等同于真正的 Turso 云端，不能证明云端区域路由、TLS、额度、凭据配置或延迟均正确。

覆盖发现元数据、所有入口无认证拒绝、完整授权、错误 PKCE、redirect/resource/client 校验、一次性授权码、过期／错误 audience／scope／owner 令牌、刷新轮换与重放、撤销、CSRF/Origin、登录限流、远端恢复、缺配置关闭，以及真实 `server.js` 的 MCP initialize、tools/list 和只读 tools/call。新增两个独立 SDK 客户端分别并发消费同一个 Code/RefreshToken 20 次，仅一次成功；断网、503、响应头/体超时、消费已提交但响应丢失、恢复和参数化 SQL 测试。

本地测试通过不等于已完成 Render 与真实 ChatGPT 的端到端验收。发布后仍需核对回调地址、HTTPS 代理、账号权限和真实连接流程。直接 HTTP 局域网启动 MCP 的旧教程不适用于本 OAuth 分支；Python Server 的局域网连接方式不变。

### Persistence v1 验收

- 自动化增加：Access token 过期后刷新、owner Session 删除及自然过期、90 天时钟推进及绝对期限、独立 Connector grants 和 revoke、失效 Interaction/cookie、真实 Node 子进程停止后重新打开同一数据库、旧 CSRF 表单拒绝、新授权恢复、跨重启 refresh rotation/replay。所有测试仅用临时密钥和本地 HTTP 服务。
- 真实验收（发布获批后）：首次连接 `/mcp` 并仅调用 `linjian_status`；等待超过 10 分钟再调用，应自动刷新而无登录页；超过 1 小时再调用，验证不依赖 owner Session。
- 经批准重启或重新部署 MCP，保留 Turso 数据库和所有 OAuth 配置；再次调用，确认授权可恢复。等待超过 15 分钟闲置后再试，允许 Render 冷启动完成，然后验证无需 owner 登录。MCP/Python 免费服务的冷启动与 OAuth 授权丢失是不同问题。
- 另开一个授权页，等待超过 5 分钟再提交，或在批准的 MCP 重启前打开、重启后提交；应提示重新发起授权。从 ChatGPT 重新发起后可以成功，不应卡在 `request_rejected`。
- 若账号界面允许建立第二个 Connector，分别验证；不把真实 token 复制出来做重放实验，重放/90 天边界使用自动化测试验证。平台是否自动 refresh 必须以真实 ChatGPT 验收为准，不能由服务器单方面保证。

参考：[OpenAI MCP Authentication](https://developers.openai.com/plugins/build/auth)、[oidc-provider 官方文档](https://github.com/panva/node-oidc-provider/tree/main/docs)、[Turso SDK / write transaction](https://docs.turso.tech/sdk/ts/reference)、[Turso 定价](https://turso.tech/pricing)。
