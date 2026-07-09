# Egress proxy — local end-to-end test

Runs `sandbox-service` with the credential-injecting egress proxy enabled inside a Linux container
(`bwrap` is Linux-only), executes a command inside the sandbox, and shows the proxy injecting an
`Authorization` header the sandbox never sent.

## Run

```bash
egress-proxy/e2e/run.sh
```

This builds the service dist (host), the sandbox rootfs image, and a runtime image; starts the
container (`--privileged`, needed so `bwrap` can create namespaces in Docker); then runs the demo.

Optional hard-enforcement demo (also installs the nftables jail and tests that direct egress is
dropped):

```bash
EGRESS_ENFORCE=true egress-proxy/e2e/run.sh
```

## What it proves

- **Injection** — `curl https://httpbin.org/headers` in the sandbox comes back with
  `"Authorization": "Bearer <DEMO_TOKEN>"`, though the command sent no such header.
- **Isolation** — the sandbox env has `HTTPS_PROXY` and the CA bundle path but no token anywhere.
- **In-path** — a request to a non-allowlisted host is refused by the proxy (`default-action = deny`).

## Manual request

```bash
curl -s -X POST localhost:7171/api/execute \
  -H "Authorization: Bearer e2e-token" -H 'Content-Type: application/json' \
  -d '{"command":"curl -s https://httpbin.org/headers","workdir":"/work","timeoutSeconds":30,"networkEnabled":true,"mounts":[]}'
```

Config lives in `application.conf`; the injected token is the `DEMO_TOKEN` env var (default
`super-secret-demo-token`).
