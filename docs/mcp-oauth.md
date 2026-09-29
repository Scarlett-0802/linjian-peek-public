# 私有掌心窗 MCP：OAuth 部署与验证

此分支保留 Android → Python Server ← Node MCP 的通信方式，只为 Node MCP 加上单用户 OAuth。不要在审阅和确认合并之前部署。本文件取代旧文档中的匿名 MCP、SSE 连接和 MCP `/health` 配置检查步骤。

## 安全边界

- 一个设备主人、一个预配置 ChatGPT OAuth 客户端；无公众注册、无动态客户端注册。
- OAuth 由固定版本 `oidc-provider` 实现：Authorization Code + 强制 PKCE S256、精确回调匹配、一次性 60 秒授权码、600 秒访问令牌。
- 访问令牌为组件生成的 opaque token，通过同一授权服务的状态验证有效性、到期、目标资源、客户端、主人和 `phone:control` 权限；不是固定 API key，也不是把手机 Token 包装为 OAuth。
- Refresh token 每次使用都会轮换；重放撤销对应 grant。Grant 和 refresh token 上限为 24 小时，到期后需再次授权。
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
| `MCP_OAUTH_DB_PATH` | 运行数据路径／可选 | 默认 `.oauth-state/oauth.sqlite`。只有日后明确选择持久磁盘时才改为挂载目录内路径。 |
| `NODE_VERSION` | 否 | Blueprint 固定 `24.19.0`，需要 Node 24 自带 SQLite。 |
| `NODE_ENV` | 否 | Blueprint 设置为 `production`。 |

现有 `LINJIAN_URL`、`LINJIAN_TOKEN`、`LINJIAN_DEFAULT_DEVICE` 保留。三个新随机 Secret 彼此必须不同，也不能与 `LINJIAN_TOKEN` 相同。修改认证密钥或回调配置会使旧授权失效。

**签名密钥只在准备配置时由你私下生成。** 在自己的终端进入 `mcp` 后运行 `node scripts/generate-jwks.js`，将唯一一行 JSON 直接复制到 Render 的 `MCP_OAUTH_JWKS`，然后清理剪贴板和终端显示；不要发给助手、写入仓库或展示截图。该脚本使用 Node 标准密码学库，不接收网络请求。本次开发测试只生成了临时测试密钥，未生成生产密钥。

当前组件支持 issuer identification，预期稳定回调为 `https://chatgpt.com/connector_platform_oauth_redirect`。配置值格式为 `["https://chatgpt.com/connector_platform_oauth_redirect"]`。**仍以你自己的 ChatGPT MCP 管理页显示的完整地址为准**；如果显示 `/connector/oauth/具体ID`，复制该精确地址。不能使用 `*`、整个域名、任意路径或前缀匹配。

如果在创建连接前还看不到回调地址，可先用上面的稳定回调预配置；得到管理页实际地址后核对，若不同则更新 Render 变量并重启，之后再登录授权。配置缺失时服务只保留存活检查，其余请求会拒绝；不能为了完成创建而关闭认证。

## 合并获批后才执行的部署顺序

1. 刷新 Blueprint，确认读取的是包含本修复的提交，而非之前缓存的 `main`。它仍只创建原来的两个服务和 shared 组。MCP 构建使用固定 pnpm 和 frozen lockfile，不执行依赖安装脚本。
2. 私下填入上述两个手动变量，保留三个自动生成 Secret。部署后验证元数据，再在 ChatGPT 创建连接。不要把 Secret 填进 GitHub 文件或 URL。

本次任务不执行以上部署。部署前应同时检查平台费用；没有新增收费数据库或磁盘配置。

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

本地普通进程重启且文件保留时可以恢复状态。Render 免费服务的文件系统是临时的，重新部署、重启或休眠都会丢失本地文件；因此需要在 ChatGPT 重新连接授权。失效不会退回匿名访问。当前不申请持久磁盘、不增加数据库服务。详见 [Render 免费实例限制](https://render.com/docs/free)。

泄漏时轮换 Render 的对应 Secret 并重启（配置命名空间变化会使既有授权全部失效），然后在 ChatGPT 重新授权。还支持标准 `/token/revocation` 撤销；不提供未认证的管理 API。

## 本地验证

在 `mcp/` 安装锁定依赖后运行 `pnpm test`。测试在本机环回地址模拟 Render 的 HTTPS 转发、浏览器登录及 ChatGPT OAuth 客户端，使用临时测试密钥及模拟 Python 后端，不控制真实手机。临时数据库结束后删除。

覆盖发现元数据、所有入口无认证拒绝、完整授权、错误 PKCE、redirect/resource/client 校验、一次性授权码、过期／错误 audience／scope／owner 令牌、刷新轮换与重放、撤销、CSRF/Origin、登录限流、SQLite 恢复、缺配置关闭，以及真实 `server.js` 的 MCP initialize、tools/list 和只读 tools/call。

本地测试通过不等于已完成 Render 与真实 ChatGPT 的端到端验收。发布后仍需核对回调地址、HTTPS 代理、账号权限和真实连接流程。直接 HTTP 局域网启动 MCP 的旧教程不适用于本 OAuth 分支；Python Server 的局域网连接方式不变。

参考：[OpenAI MCP Authentication](https://developers.openai.com/plugins/build/auth)、[oidc-provider 官方文档](https://github.com/panva/node-oidc-provider/tree/main/docs)。
