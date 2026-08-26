# plist

Aggregated list of public Telegram proxies (MTProto / SOCKS5), rebuilt
automatically every 6 hours by a GitHub Action.

## What this repo publishes

| File | Purpose |
|---|---|
| `docs/list.json` | The payload clients fetch. Schema below. |
| `docs/list.json.sig` | Detached ECDSA P-256 / SHA-256 signature of `list.json`, base64 (DER encoding). |
| `heartbeat.txt` | UTC timestamp rewritten on every run. Exists only to keep the scheduled workflow alive; clients must ignore it. |

## Endpoints

- GitHub Pages: `https://David98mo.github.io/plist/list.json`
- jsDelivr: `https://cdn.jsdelivr.net/gh/David98mo/plist@main/docs/list.json`
- raw: `https://raw.githubusercontent.com/David98mo/plist/main/docs/list.json`
- Cloudflare Pages: `https://plist.pages.dev/list.json`

Any one of these may be unreachable from a given network. Clients are expected
to race all of them and take the first valid response.

## Schema (`schema_version: 1`)

```json
{
  "schema_version": 1,
  "generated_at": "2026-01-01T00:00:00Z",
  "ttl_seconds": 21600,
  "mirrors": ["https://..."],
  "proxies": [
    { "type": "mtproto", "host": "1.2.3.4", "port": 443, "secret": "ee..." },
    { "type": "socks5",  "host": "1.2.3.4", "port": 1080 }
  ]
}
```

Consumers must reject the whole payload if it is larger than 2 MB, is not valid JSON, has a schema_version greater than the one they understand, or is missing proxies. Individual malformed entries should be dropped, not fatal.

### Why list.json is only rewritten when the content changes
Clients issue conditional requests (If-None-Match / If-Modified-Since) and rely on HTTP 304 to avoid downloading an unchanged list. Every commit that touches list.json mints a new ETag, so committing an unchanged file on every run would defeat caching entirely. The build therefore compares only the proxies array and skips the commit when nothing changed. The heartbeat lives in a separate file for exactly this reason.

### Running this yourself
Fork the repo.
Settings -> Pages -> Deploy from a branch -> main -> /docs.
Settings -> Actions -> General -> Workflow permissions -> Read and write.
Generate a signing key and add the private half as the SIGNING_KEY secret: 
`openssl ecparam -name prime256v1 -genkey -noout -out private.pem`
`openssl ec -in private.pem -pubout -outform DER | base64 | tr -d '\n' > pubkey.b64`

Edit src/sources.json with the upstream lists you want aggregated.
Run the workflow manually once from the Actions tab.

### No proxies are operated by this project
This repository only aggregates lists that are already public. It runs no proxy servers and makes no claim that any listed proxy works, is safe, or is fast. Nothing here is tested from inside any particular network — testing is the client's job.

### License
MIT.