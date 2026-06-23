# Gemini Router

Gemini Router 是一个轻量级 Go 服务，用于在本地或服务器上接收用户请求，并使用管理页面中配置的 Gemini API Key 转发到 Google Gemini 官方 API 端点。项目内置简单的 Web 管理页面，支持项目 API Key、全局 SOCKS5 代理、Gemini Key 列表和单 Key SOCKS5 代理配置。

## 功能特性

- 转发 `/v1/` 与 `/v1beta/` 请求到 Gemini 官方 API：`https://generativelanguage.googleapis.com`。
- 使用项目 API Key 保护代理接口；未配置项目 API Key 时不鉴权，方便首次部署。
- Web 管理页面：访问 `http://localhost:8080/admin`。
- 支持配置：
  - 项目 API Key。
  - 项目默认 SOCKS5 代理。
  - 多个 Gemini API Key。
  - 每个 Gemini API Key 的备注。
  - 每个 Gemini API Key 的单独 SOCKS5 代理。
- Gemini Key 管理：添加、批量添加、删除、测试有效性。
- 多 Key 轮询转发，优先跳过最近测试失败的 Key。
- 支持 Docker 与 Docker Compose 一键部署。

## 快速开始

### 使用 Docker Compose

```bash
docker compose up -d --build
```

服务启动后打开：

```text
http://localhost:8080/admin
```

首次进入时项目 API Key 为空，不需要鉴权。建议进入管理页后立即设置项目 API Key。

### 本地运行

需要 Go 1.22 或更高版本：

```bash
go mod download
go run .
```

默认监听 `:8080`，配置文件默认保存到 `./data/config.json`。

## 配置项

可以通过环境变量修改运行配置：

| 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `ADDR` | `:8080` | HTTP 监听地址 |
| `DATA_PATH` | `./data/config.json` | 配置文件保存路径 |
| `GEMINI_ENDPOINT` | `https://generativelanguage.googleapis.com` | Gemini 官方 API 端点 |

SOCKS5 代理地址格式示例：

```text
socks5://127.0.0.1:1080
socks5://user:pass@proxy.example.com:1080
```

## 管理页面使用方法

1. 打开 `http://localhost:8080/admin`。
2. 在“项目配置”中设置项目 API Key 和项目默认 SOCKS5 代理。
3. 在“添加 Gemini Key”中粘贴一个或多个 Gemini API Key，每行一个。
4. 如某些 Gemini Key 需要记录用途、来源或环境，可填写备注，并可在 Key 列表中随时修改。
5. 如某些 Gemini Key 需要独立代理，可在添加时填写代理，也可以在 Key 列表中单独修改。
6. 点击“测试”或“测试全部 Key”检查 Key 是否可用。
7. 后续如果设置了项目 API Key，访问管理页面时会自动跳转到 `/login`，使用项目 API Key 登录后即可进入管理页面。

管理接口仍支持通过 `X-API-Key` 请求头访问，便于脚本化操作。

## 代理调用示例

列出模型：

```bash
curl -H 'X-API-Key: 你的项目APIKey' \
  http://localhost:8080/v1beta/models
```

生成内容：

```bash
curl -X POST \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: 你的项目APIKey' \
  'http://localhost:8080/v1beta/models/gemini-1.5-flash:generateContent' \
  -d '{
    "contents": [
      {"parts": [{"text": "Hello"}]}
    ]
  }'
```

Gemini Router 会自动选择一个已配置的 Gemini API Key，并将请求转发到官方端点。客户端请求中的 `key` 查询参数会被服务端配置的 Gemini Key 覆盖。

## 数据持久化

配置会以 JSON 文件保存到 `DATA_PATH` 指定的位置。Docker Compose 默认使用名为 `gemini-router-data` 的 volume 持久化 `/data/config.json`。

请妥善保护该配置文件，因为其中包含项目 API Key 和 Gemini API Key。

## 健康检查

```bash
curl http://localhost:8080/healthz
```

返回 `ok` 表示服务正在运行。

## 安全建议

- 部署后立即设置项目 API Key。
- 不要将 `/admin` 暴露到公网；建议放在内网、VPN 或反向代理鉴权之后。
- 定期测试并清理失效 Gemini Key。
- 如果使用 SOCKS5 代理，优先使用可信代理服务。
