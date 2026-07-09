# Egress proxy — credential injection for the sandbox

Injects auth headers into outbound HTTP/HTTPS calls the agent's sandbox makes to specific domains,
**without the token ever entering the sandbox**. A call to e.g. Jira goes out with
`Authorization: Bearer <token>` added by the proxy, even though the sandboxed command never had the
token and never sent the header.

## How it works

The proxy runs **inside the `sandbox-service` JVM**, as the parent that launches the `bwrap`
sandbox — it is *not* itself sandboxed. The sandbox is pointed at it via `HTTPS_PROXY`.

```
 Container / host
 ┌───────────────────────────────────────────────────────────────┐
 │ sandbox-service (JVM)                                           │
 │   • egress proxy runs here; holds the token (config + memory)   │
 │        │ spawns                                                 │
 │        ▼                                                        │
 │   bwrap sandbox (uid 65534, own user/pid/ipc/MOUNT ns)          │
 │        curl ──TLS #1──▶ proxy ──TLS #2──▶ real upstream         │
 │        trusts our CA    (MITM, injects)   proxy validates the   │
 │        (mounted bundle)  header here      real cert normally    │
 └───────────────────────────────────────────────────────────────┘
        shared network namespace → sandbox reaches proxy on 127.0.0.1:<port>
```

Request flow:
1. The sandbox has `HTTPS_PROXY=http://127.0.0.1:<port>` set. A proxy-aware client (curl, git,
   pip, requests…) sends `CONNECT host:443` to the proxy — **it does not resolve DNS itself**; the
   proxy resolves and dials the upstream. No DNS interception/faking is needed.
2. The proxy checks its **policy** (first-match-wins on the host from `CONNECT`/SNI):
   - **terminate** → present a leaf cert minted by our CA, decrypt, inject the configured header,
     re-originate a fresh validated TLS connection to the real upstream.
   - **tunnel** → blind byte relay; the upstream's real cert reaches the client (cert-pinning-safe,
     no injection).
   - **deny / default-action deny** → refuse the connection.
3. The header value comes from a credential resolved by the matched **rule** — never from anything
   the sandbox sent, so injection can't be spoofed.

## Why the token is safe

The proxy (JVM) and the sandbox are **separate processes**. The token lives only in the proxy's
memory and its config file — neither is in the sandbox's mount namespace, and one process can't read
another's memory. The sandbox only sees its rootfs, its workdir, and the **public** CA bundle. So
sandboxed code cannot read or steal the token. (Sharing a network namespace only shares loopback —
it grants no access to files or memory.)

### Soft vs hard enforcement

- **Soft (default, `enforce = false`)** — guarantees the token stays out of the sandbox. It does
  **not** force all traffic through the proxy: `HTTPS_PROXY` is a convention, so a tool that ignores
  it (Node core, raw sockets) or a command that runs `unset HTTPS_PROXY` can reach the network
  directly. Right when you trust the sandboxed code not to be actively hostile about egress.
- **Hard (`enforce = true`)** — additionally installs an nftables jail so the sandbox can *only*
  reach the proxy (no bypass, no data exfiltration). Requires Linux + CAP_NET_ADMIN. **Note:** the
  current owner-match implementation is incompatible with bwrap's `--uid`; hard mode needs the
  cgroup-match or separate-process redesign before it's usable. Leave it off unless/until that lands.

## CA & trust

Three trust relationships:
- **CA (per instance):** a self-signed CA generated on first start and persisted to
  `<state-dir>/ca.{crt,key}` (key `0600`), reloaded on restart. The **private key never leaves the
  proxy** and is never mounted into the sandbox.
- **Sandbox → proxy (TLS #1):** on start the proxy writes a **combined bundle** (rootfs system CAs +
  our CA) and bind-mounts it read-only over `/etc/ssl/certs/ca-certificates.crt`, plus sets
  `CURL_CA_BUNDLE`/`SSL_CERT_FILE`/`GIT_SSL_CAINFO`/`NODE_EXTRA_CA_CERTS`/`REQUESTS_CA_BUNDLE`/
  `PIP_CERT`. Because it includes the original system CAs, tunneled hosts with real certs still
  validate.
- **Proxy → upstream (TLS #2):** the proxy validates the real server's cert against the default
  system/JDK trust store with hostname verification — it's a normal TLS client.

## Configuration

Everything is one HOCON block in the `sandbox-service` config (see
`sandbox-service/src/main/resources/application.conf.sample`), loaded via `-config=`. The app/`tools`
side is unchanged.

```hocon
egress {
  enabled = true
  port = 0                       # ephemeral local port
  state-dir = "data/egress"      # CA persisted here
  default-action = deny          # deny | tunnel
  # enforce = false              # soft mode (see above)

  credentials = [                # secret comes from an env var, never the file
    { ref = jira-token, value = ${?JIRA_TOKEN} }
  ]
  rules = [
    { id = jira, host = "*.atlassian.net", path-prefix = "/rest/", action = terminate,
      credential-ref = jira-token, header = "Authorization", value-template = "Bearer {{token}}" }
  ]
}
```

Set the token via the referenced env var on the service process/container (e.g. `-e JIRA_TOKEN=...`).
Add services by adding a credential + a matching rule. `{{token}}` in `value-template` is where the
secret is substituted.

## Which clients honor `HTTPS_PROXY`

Injection only happens for proxy-aware clients: **curl, git (HTTPS remotes), wget, pip, Python
requests/urllib, Go net/http**. Notably **not** honored by default: **Node core** (needs
`NODE_EXTRA_CA_CERTS` + a proxy agent), the **JVM** (uses `-Dhttps.proxyHost`), **SSH**, and raw
sockets. curl reads `HTTPS_PROXY`/`https_proxy` for HTTPS but only lowercase `http_proxy` for HTTP,
so both cases are set.

## Layout

- `net/` — Netty proxy: `EgressProxyServer`, `ConnectHandler`, `MitmRequestHandler`, `RelayHandler`,
  `ProxySslContexts`.
- `policy/` — `EgressPolicy` / `EgressRule` (first-match-wins matcher).
- `ca/` — `ProxyCa` (CA gen/persist), `LeafCertFactory` (per-SNI leaves).
- `cred/` — `CredentialSource` / `ConfigCredentialSource`, `Secret` (CharArray, zeroed after use).
- Service wiring: `sandbox-service/.../EgressServiceConfig`, `EgressProxyRuntime`, `NftablesJail`.
- `e2e/` — runnable local end-to-end demo (`e2e/run.sh`), see `e2e/README.md`.
