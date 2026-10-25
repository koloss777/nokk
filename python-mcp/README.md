# nokk-mcp

<!-- mcp-name: io.github.koloss777/nokk -->

An MCP server that gives an AI agent a headless browser: [nokk](https://github.com/koloss777/nokk),
a Rust engine with Chrome 151's TLS, HTTP/2 and JavaScript fingerprint that passes Cloudflare's
challenges without Chromium.

```bash
uvx nokk-mcp
```

Client configuration (Claude Desktop, Claude Code, Cursor and others):

```json
{
  "mcpServers": {
    "nokk": { "command": "uvx", "args": ["nokk-mcp"] }
  }
}
```

Tools: `open`, `snapshot`, `read_text`, `read_html`, `click`, `fill`, `evaluate`, `links`, `solve_challenge`,
`challenge_state`, `reset`. `open` solves a Cloudflare challenge on the way and says what it met.

Options (flags or environment variables):

| Flag | Variable | What it does |
|---|---|---|
| `--proxy URL` | `NOKK_PROXY` | upstream proxy, e.g. `socks5://host:1080` |
| `--rotate-fingerprint` | `NOKK_ROTATE_FINGERPRINT=1` | each session gets its own coherent fingerprint |
| `--geoip-timezone` | `NOKK_GEOIP_TIMEZONE=1` | timezone and locale follow the proxy's exit IP |
| `--session-store DIR` | `NOKK_SESSION_STORE` | keep named sessions' cookies on disk |
| `--no-auto-solve` | `NOKK_NO_AUTO_SOLVE=1` | do not solve challenges during navigation |
| `--workers N` | `NOKK_WORKERS` | isolate worker threads |

The same server runs as `python -m nokk.mcp` after `pip install "nokk[mcp]"`.
Documentation, the CDP server and the Python and Node launchers: https://github.com/koloss777/nokk
