#!/usr/bin/env bash
# End-to-end test of the credential-injecting egress proxy.
#
# Boots sandbox-service (with the proxy enabled) inside a Linux container, runs
#   curl https://httpbin.org/headers
# inside the bwrap sandbox, and shows httpbin echoing back an Authorization header the sandbox
# never sent - proving the proxy injected it and the token never entered the sandbox.
#
# Usage:  egress-proxy/e2e/run.sh
# Env:    DEMO_TOKEN   (default: super-secret-demo-token)
#         EGRESS_ENFORCE=true   also install the nftables jail and test bypass (needs --privileged)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

DEMO_TOKEN="${DEMO_TOKEN:-super-secret-demo-token}"
EGRESS_ENFORCE="${EGRESS_ENFORCE:-false}"
SANDBOX_TOKEN="e2e-token"
CONTAINER="egress-e2e"
PORT=7171

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "==> [1/4] Building sandbox-service dist (host)"
./gradlew :sandbox-service:installDist -q

echo "==> [2/4] Building sandbox rootfs image"
docker build -q -t sidekick-sandbox-rootfs "$REPO_ROOT/sandbox" >/dev/null

echo "==> [3/4] Building e2e runtime image"
docker build -q -f "$SCRIPT_DIR/Dockerfile" -t sidekick-egress-e2e "$REPO_ROOT" >/dev/null

echo "==> [4/4] Starting container (enforce=$EGRESS_ENFORCE)"
cleanup
docker run --rm -d --name "$CONTAINER" --privileged \
    -p "$PORT:7171" \
    -e "DEMO_TOKEN=$DEMO_TOKEN" \
    -e "EGRESS_ENFORCE=$EGRESS_ENFORCE" \
    sidekick-egress-e2e >/dev/null

# execute <json-command> -> prints the sandbox output
execute() {
    curl -s -X POST "localhost:$PORT/api/execute" \
        -H "Authorization: Bearer $SANDBOX_TOKEN" \
        -H 'Content-Type: application/json' \
        -d "$1"
}

req() {
    local cmd="$1"
    printf '{"command":%s,"workdir":"/work","timeoutSeconds":30,"networkEnabled":true,"mounts":[]}' \
        "$(printf '%s' "$cmd" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')"
}

echo -n "==> Waiting for service"
for _ in $(seq 1 60); do
    if curl -s -o /dev/null "localhost:$PORT/api/execute" -X POST -H "Authorization: Bearer $SANDBOX_TOKEN" 2>/dev/null; then
        break
    fi
    echo -n "."; sleep 1
done
echo " ready"
sleep 1

extract_output() { python3 -c 'import json,sys; print(json.load(sys.stdin).get("output",""))'; }

echo
echo "=== 1. Injection: curl https://httpbin.org/headers (sandbox sends NO auth header) ==="
execute "$(req 'curl -s https://httpbin.org/headers')" | extract_output

echo
echo "=== 2. Secret isolation: proxy env is present, token is NOT ==="
execute "$(req 'echo "--- proxy/ca env ---"; env | grep -iE "proxy|ca_bundle|cert" | sort; echo "--- any token? ---"; env | grep -i token || echo "(no token in env)"')" | extract_output

echo
echo "=== 3. Proxy in path: a non-allowlisted host is refused ==="
execute "$(req 'curl -s -o /dev/null -w "http_code=%{http_code} exit=%{exitcode}\n" https://example.com || echo "curl failed (expected: proxy denied CONNECT)"')" | extract_output

if [ "$EGRESS_ENFORCE" = "true" ]; then
    echo
    echo "=== 4. Hard enforcement: direct (non-proxied) egress is dropped ==="
    execute "$(req 'echo "proxied:"; curl -s -o /dev/null -w "  http_code=%{http_code}\n" https://httpbin.org/get; echo "direct (--noproxy, should time out):"; curl -s --noproxy "*" -m 5 -o /dev/null -w "  http_code=%{http_code}\n" https://httpbin.org/get || echo "  blocked (expected)"')" | extract_output
    echo "--- nft ruleset in container ---"
    docker exec "$CONTAINER" nft list ruleset 2>/dev/null | grep -A8 sidekick_egress || echo "(no ruleset)"
fi

echo
echo "==> Done. (container will be removed)"
