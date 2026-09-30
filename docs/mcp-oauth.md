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
| `MCP_OAUTH_DB_PATH` | 非 Secret／Render 必填 | `/var/data/mcp-oauth/oauth.sqlite`，必须位于真实持久磁盘的挂载目录内。`RENDER=true` 时拒绝缺省或相对路径；路径配置本身不能创建持久磁盘。本地开发仍默认 `.oauth-state/oauth.sqlite`。 |
| `NODE_VERSION` | 否 | Blueprint 固定 `24.19.0`，需要 Node 24 自带 SQLite。 |
| `NODE_ENV` | 否 | Blueprint 设置为 `production`。 |

现有 `LINJIAN_URL`、`LINJIAN_TOKEN`、`LINJIAN_DEFAULT_DEVICE` 保留。三个新随机 Secret 彼此必须不同，也不能与 `LINJIAN_TOKEN` 相同。修改认证密钥或回调配置会使旧授权失效。

**签名密钥只在准备配置时由你私下生成。** 在自己的终端进入 `mcp` 后运行 `node scripts/generate-jwks.js`，将唯一一行 JSON 直接复制到 Render 的 `MCP_OAUTH_JWKS`，然后清理剪贴板和终端显示；不要发给助手、写入仓库或展示截图。该脚本使用 Node 标准密码学库，不接收网络请求。本次开发测试只生成了临时测试密钥，未生成生产密钥。

当前组件支持 issuer identification，预期稳定回调为 `https://chatgpt.com/connector_platform_oauth_redirect`。配置值格式为 `["https://chatgpt.com/connector_platform_oauth_redirect"]`。**仍以你自己的 ChatGPT MCP 管理页显示的完整地址为准**；如果显示 `/connector/oauth/具体ID`，复制该精确地址。不能使用 `*`、整个域名、任意路径或前缀匹配。

如果在创建连接前还看不到回调地址，可先用上面的稳定回调预配置；得到管理页实际地址后核对，若不同则更新 Render 变量并重启，之后再登录授权。配置缺失时服务只保留存活检查，其余请求会拒绝；不能为了完成创建而关闭认证。

## 合并获批后才执行的部署顺序

1. 在 MCP 服务的 Settings 中选择付费实例（Blueprint 为 `starter`），保持单实例；Python 服务不变。先查看当前价格，只有批准费用和部署后才操作。
2. 在 MCP 的 Disks 页面添加 1 GB 磁盘，挂载 `/var/data/mcp-oauth`；在 Environment 设置 `MCP_OAUTH_DB_PATH=/var/data/mcp-oauth/oauth.sqlite`。保留所有现有 Secret、issuer 和回调，不重新生成。添加磁盘和保存环境变量可能触发部署，应在同一次批准的发布窗口操作。
3. 获批合并后发布本修复，并核对 Blueprint 与 UI 一致。`render.yaml` 已声明付费 MCP、磁盘及数据库路径；若使用 Blueprint 同步，先审阅资源费用，勿把它当作无成本刷新。发布后在 ChatGPT 重新授权一次，开始新的 90 天授权期。

本次任务仅提交配置，不执行以上操作、不购买资源。仅升级付费实例而不挂载磁盘仍会丢失 SQLite。旧临时数据库中的授权不会自动搬到新磁盘；旧 24 小时授权也不会自动升级期限，因此切换时需要重新授权一次。

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

OAuth 状态保存在该 Node 实例的 SQLite 中，包含运行时会话和令牌记录，**这是敏感运行数据，不是源码或环境配置 Secret**，不会提交 GitHub；Linux 下目录和数据库限制为仅服务用户访问。单实例运行，不支持多实例横向扩容。

本地普通进程重启且文件保留时可以恢复状态。Render 免费服务的文件系统是临时的，重新部署、重启或休眠都会丢失本地文件；免费实例不能挂载持久磁盘。该方案需付费 MCP 实例及持久磁盘，付费实例不会按免费服务的规则休眠。磁盘保留时，重启和重新部署不要求重新授权，但重启期间服务会短暂不可用。详见 [Render 免费实例限制](https://render.com/docs/free) 和 [持久磁盘](https://render.com/docs/disks)。不切换 Postgres/Redis，不支持多实例共享 SQLite。

Interaction/授权码保持 5 分钟/60 秒有效期，均通过 SQLite 保存。表单 CSRF nonce 故意仍只保存在进程内存：重启后旧表单安全失败，并提示关闭页面、返回 ChatGPT 重新发起授权。失效 Interaction、缺失或不匹配的 cookie/路径也给出同一提示；不自动构造新的授权 URL，不绕过 Origin/CSRF，不回显异常或凭据。已完成授权的 refresh token 不依赖这个 Map。

正常重新部署必须保持数据库和配置密钥不变。主动撤销、90 天期限届满、检测到令牌重放，或 issuer/owner secret/cookie secret/client secret/JWKS/回调配置变化会要求重新授权。后者沿用原有命名空间隔离策略。不要通过恢复旧数据库快照撤销已发生的 revoke/rotation；灾难恢复需使旧授权失效后重新授权。数据库包含敏感令牌，不能提交 GitHub、下载到聊天或记录到日志。

泄漏时轮换 Render 的对应 Secret 并重启（配置命名空间变化会使既有授权全部失效），然后在 ChatGPT 重新授权。还支持标准 `/token/revocation` 撤销；不提供未认证的管理 API。

## 本地验证

在 `mcp/` 安装锁定依赖后运行 `pnpm test`。测试在本机环回地址模拟 Render 的 HTTPS 转发、浏览器登录及 ChatGPT OAuth 客户端，使用临时测试密钥及模拟 Python 后端，不控制真实手机。临时数据库结束后删除。

覆盖发现元数据、所有入口无认证拒绝、完整授权、错误 PKCE、redirect/resource/client 校验、一次性授权码、过期／错误 audience／scope／owner 令牌、刷新轮换与重放、撤销、CSRF/Origin、登录限流、SQLite 恢复、缺配置关闭，以及真实 `server.js` 的 MCP initialize、tools/list 和只读 tools/call。

本地测试通过不等于已完成 Render 与真实 ChatGPT 的端到端验收。发布后仍需核对回调地址、HTTPS 代理、账号权限和真实连接流程。直接 HTTP 局域网启动 MCP 的旧教程不适用于本 OAuth 分支；Python Server 的局域网连接方式不变。

### Persistence v1 验收

- 自动化增加：Access token 过期后刷新、owner Session 删除及自然过期、90 天时钟推进及绝对期限、独立 Connector grants 和 revoke、失效 Interaction/cookie、真实 Node 子进程停止后重新打开同一数据库、旧 CSRF 表单拒绝、新授权恢复、跨重启 refresh rotation/replay。所有测试仅用临时密钥和本地 HTTP 服务。
- 真实验收（发布获批后）：首次连接 `/mcp` 并仅调用 `linjian_status`；等待超过 10 分钟再调用，应自动刷新而无登录页；超过 1 小时再调用，验证不依赖 owner Session。
- 经批准重启或重新部署 MCP，保留磁盘和所有配置；再次调用，确认授权可恢复。等待 15 分钟闲置后再试，付费 MCP 应仍可用；Python 免费服务可能独立冷启动，这不属于 OAuth 失效。
- 另开一个授权页，等待超过 5 分钟再提交，或在批准的 MCP 重启前打开、重启后提交；应提示重新发起授权。从 ChatGPT 重新发起后可以成功，不应卡在 `request_rejected`。
- 若账号界面允许建立第二个 Connector，分别验证；不把真实 token 复制出来做重放实验，重放/90 天边界使用自动化测试验证。平台是否自动 refresh 必须以真实 ChatGPT 验收为准，不能由服务器单方面保证。

参考：[OpenAI MCP Authentication](https://developers.openai.com/plugins/build/auth)、[oidc-provider 官方文档](https://github.com/panva/node-oidc-provider/tree/main/docs)。
