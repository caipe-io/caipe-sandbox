# Dedicated coding profile: no unrelated harnesses or platform credentials.
FROM node:24-bookworm-slim@sha256:c86ecead9e55a5210ac1727de38a4ca840bf03dcaf34dc9749addbf383b1920c AS acp
WORKDIR /opt/claude-acp
RUN npm install --omit=dev --ignore-scripts --save-exact @agentclientprotocol/claude-agent-acp@0.100.0

FROM python:3.12-slim@sha256:cb33f7f771ecec2ef1225cf39b159591a040391bd73e4c01f00fdfc4c47611d2
LABEL org.opencontainers.image.source="https://github.com/caipe-io/caipe-sandbox" \
      org.opencontainers.image.title="Claude ACP coding environment"
RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends bash git openssh-client ripgrep jq less ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir supervisor==4.3.0
COPY --from=acp /usr/local/bin/node /usr/local/bin/node
COPY --from=acp /opt/claude-acp /opt/claude-acp
COPY sandbox-images/common-tools/sandbox/ /usr/local/lib/sandbox/
COPY sandbox-images/claude-code/acp_runner.py /usr/local/lib/sandbox/acp_runner.py
RUN printf '#!/bin/sh\nexec node /opt/claude-acp/node_modules/@agentclientprotocol/claude-agent-acp/dist/index.js "$@"\n' > /usr/local/bin/claude-agent-acp \
 && printf '#!/bin/sh\nexec /opt/venv/bin/python /usr/local/lib/sandbox/runtime.py start "$@"\n' > /usr/local/bin/sandbox-start \
 && printf '#!/bin/sh\nexec /opt/venv/bin/python /usr/local/lib/sandbox/runtime.py control "$@"\n' > /usr/local/bin/sandbox-control \
 && chmod 0555 /usr/local/bin/claude-agent-acp /usr/local/bin/sandbox-start /usr/local/bin/sandbox-control \
 && chmod -R go-w /usr/local/lib/sandbox /opt/claude-acp \
 && mkdir -p /home/sandbox \
 && chown 1000:1000 /home/sandbox
ENV HOME=/home/sandbox \
    PATH=/opt/venv/bin:$PATH
WORKDIR /home/sandbox
# Exercise the actual entrypoint as an arbitrary Kubernetes UID. This catches
# missing runtime executables and verifies the control socket before publishing.
USER 1000660000:1000660000
RUN set -eu; \
    smoke_home="$(mktemp -d)"; export HOME="$smoke_home"; \
    sandbox-start > "$smoke_home/startup.log" 2>&1 & smoke_pid=$!; \
    trap 'kill "$smoke_pid" 2>/dev/null || true; wait "$smoke_pid" 2>/dev/null || true' EXIT; \
    count=0; \
    until [ -S "$HOME/.local/state/sandbox/supervisor.sock" ]; do \
      if ! kill -0 "$smoke_pid" 2>/dev/null || [ "$count" -ge 50 ]; then cat "$HOME/startup.log"; exit 1; fi; \
      count=$((count + 1)); sleep 0.1; \
    done; \
    printf '{"action":"inspect"}\n' | sandbox-control | /opt/venv/bin/python -c 'import json, sys; result=json.load(sys.stdin); assert "error" not in result, result'; \
    kill "$smoke_pid"; wait "$smoke_pid" || true; trap - EXIT; \
    /opt/venv/bin/python -c 'import os, shutil; shutil.rmtree(os.environ["HOME"])'
USER 1000:1000
CMD ["sandbox-start"]
