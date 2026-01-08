# 域名白名单过滤设计方案

## 概述

将现有的路由规则机制简化为域名白名单过滤功能。移除多 backend 支持，只保留单一全局 SOCKS5 代理，通过白名单控制允许访问的域名。

## 需求

1. **白名单模式**：只有匹配规则的域名才允许通过
2. **灵活通配符**：支持多个 `*` 的通配符模式（如 `*.prod.*.internal`）
3. **默认允许**：未配置规则时允许所有域名
4. **配置简化**：使用简洁的数组格式

## 配置结构

### 新配置格式

```toml
[server]
listen_addr = "0.0.0.0:443"

[socks5]
addr = "127.0.0.1:1080"

[rules]
# 空 allow 数组 = 允许所有域名
allow = [
    "*.google.com",
    "api.*.com",
    "*.prod.*.internal"
]
```

### 行为说明

| 配置 | 行为 |
|------|------|
| `allow = []` 或不配置 `rules` | 允许所有域名 |
| `allow = ["*.google.com"]` | 只允许匹配 `*.google.com` 的域名 |

## 通配符匹配规则

### 匹配示例

| 模式 | 匹配 | 不匹配 |
|------|------|--------|
| `*google.com` | `google.com`, `www.google.com`, `mail.google.com` | `evil.com` |
| `*.google.com` | `www.google.com`, `mail.google.com` | `google.com`, `evil.com` |
| `api.*.com` | `api.example.com`, `api.foo.com` | `api.com`, `www.api.com` |
| `*.prod.*.internal` | `web.prod.db.internal`, `api.prod.cache.internal` | `dev.prod.db.internal` |

### 关键区别

- `*google.com` - 前缀通配，**包括自身**
- `*.google.com` - 子域名通配，**不包括自身**

## 代码变更

### 1. 配置结构 (config.rs)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub socks5: Socks5Config,
    #[serde(default)]
    pub rules: RulesConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RulesConfig {
    /// 白名单域名模式，空数组表示允许所有域名
    #[serde(default)]
    pub allow: Vec<String>,
}
```

**移除**：
- `rules.default_backend`
- `rules.domain`
- `DomainRule.backend`

### 2. 路由器 (router.rs)

```rust
impl Router {
    /// 检查域名是否被允许
    pub fn is_allowed(&self, hostname: &str) -> bool {
        // 空 allow 数组 → 允许所有
        if self.config.rules.allow.is_empty() {
            return true;
        }

        // 检查是否匹配任一模式
        self.config.rules.allow
            .iter()
            .any(|pattern| self.match_pattern(hostname, pattern))
    }

    /// 灵活通配符匹配
    fn match_pattern(&self, hostname: &str, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }

        let parts: Vec<&str> = pattern.split('*').collect();
        let mut pos = 0;

        for (i, part) in parts.iter().enumerate() {
            if part.is_empty() {
                continue;
            }

            if let Some(idx) = hostname[pos..].find(part) {
                pos += idx + part.len();

                if i == parts.len() - 1 {
                    if pattern.ends_with('*') {
                        return true;
                    }
                    return pos == hostname.len();
                }
            } else {
                return false;
            }
        }

        true
    }
}
```

**移除**：
- `RouteDecision` 结构体
- `route()` 方法

### 3. TCP 代理集成 (tcp/mod.rs)

```rust
async fn handle_client(
    client_stream: TcpStream,
    client_addr: SocketAddr,
    socks5_client: Socks5Client,
    router: Arc<Router>,  // 新增参数
) -> Result<()> {
    // ... 提取 SNI ...

    let sni = match extract_sni(&buffer[..n])? {
        Some(hostname) => hostname,
        None => bail!("No SNI found"),
    };

    // 白名单检查
    if !router.is_allowed(&sni) {
        warn!("Domain {} not in whitelist, rejecting", sni);
        return Err(anyhow!("Domain not allowed: {}", sni));
    }

    // 允许通过，继续 SOCKS5 连接
    let proxy_stream = socks5_client.connect(&sni, 443).await?;
    // ...
}
```

## 测试用例

```rust
#[test]
fn test_empty_rules_allow_all() {
    let config = Config {
        rules: RulesConfig { allow: vec![] },
        // ...
    };
    let router = Router::new(config);

    assert!(router.is_allowed("google.com"));
    assert!(router.is_allowed("any.domain.com"));
}

#[test]
fn test_wildcard_with_self() {
    let config = Config {
        rules: RulesConfig { allow: vec!["*google.com".to_string()] },
        // ...
    };
    let router = Router::new(config);

    assert!(router.is_allowed("google.com"));      // 自身
    assert!(router.is_allowed("www.google.com"));  // 子域名
}

#[test]
fn test_wildcard_subdomain_only() {
    let config = Config {
        rules: RulesConfig { allow: vec!["*.google.com".to_string()] },
        // ...
    };
    let router = Router::new(config);

    assert!(!router.is_allowed("google.com"));     // 不包括自身
    assert!(router.is_allowed("www.google.com"));
}

#[test]
fn test_multi_wildcard() {
    let config = Config {
        rules: RulesConfig {
            allow: vec!["*.prod.*.internal".to_string()]
        },
        // ...
    };
    let router = Router::new(config);

    assert!(router.is_allowed("web.prod.db.internal"));
    assert!(router.is_allowed("api.prod.cache.internal"));
    assert!(!router.is_allowed("dev.prod.db.internal"));
}
```

## 迁移路径

1. 修改 `config.rs` - 简化配置结构
2. 修改 `router.rs` - 重写匹配逻辑
3. 修改 `tcp/mod.rs` - 集成白名单检查
4. 更新测试用例
5. 更新文档
