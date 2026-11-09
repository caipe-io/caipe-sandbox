# syntax=docker/dockerfile:1.7
FROM node:22-bookworm-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d AS browser
ADD --checksum=sha256:cbcf4cc03148ccdb586a8bf2093c952f093fb43d5cbc97593c98b67ef8c003b0 https://registry.npmjs.org/npm/-/npm-11.11.0.tgz /tmp/npm.tgz
RUN npm install --global --ignore-scripts /tmp/npm.tgz && rm /tmp/npm.tgz
WORKDIR /app
COPY apps/portal/package*.json apps/portal/.npmrc ./
RUN npm ci --ignore-scripts
COPY apps/portal/build.mjs ./
COPY apps/portal/web/ ./web/
COPY apps/portal/portal/static/index.html ./portal/static/index.html
COPY apps/portal/portal/static/caipe-sandbox-logo.png ./portal/static/caipe-sandbox-logo.png
RUN npm test && npm run build

FROM browser AS browser-audit
ARG SECURITY_AUDIT_ID
RUN printf 'Dependency audit %s\n' "$SECURITY_AUDIT_ID" && npm audit

FROM ghcr.io/astral-sh/uv:0.12.17@sha256:10787c682e4184e4f290de1171fd4703dc63de99221f10fe1c99002ce7fa9acc AS uv
FROM python:3.12-slim@sha256:cb33f7f771ecec2ef1225cf39b159591a040391bd73e4c01f00fdfc4c47611d2 AS dependencies
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /repo/apps/portal
ENV UV_PROJECT_ENVIRONMENT=/opt/venv UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
COPY apps/portal/pyproject.toml apps/portal/uv.lock ./
RUN uv sync --locked --no-default-groups --no-install-project --no-editable --no-build

FROM dependencies AS test
ENV UV_PROJECT_ENVIRONMENT=/opt/test-venv PYTHONPATH=/repo/sandbox-images/common-tools
COPY apps/portal/portal/ ./portal/
COPY apps/portal/tests/ ./tests/
COPY sandbox-images/common-tools/ /repo/sandbox-images/common-tools/
COPY sandbox-images/claude-code/acp_runner.py /repo/sandbox-images/claude-code/acp_runner.py
COPY apps/portal/examples/ ./examples/
COPY charts/ /repo/charts/
COPY --from=browser /app/portal/static/ ./portal/static/
RUN uv sync --locked --extra test --group build --no-install-project --no-editable --no-build \
 && /opt/test-venv/bin/python -m pytest -q \
 && /opt/test-venv/bin/python -m pip wheel --no-build-isolation --no-deps --wheel-dir /wheels .

FROM test AS audit
ARG SECURITY_AUDIT_ID
RUN printf 'Dependency audit %s\n' "$SECURITY_AUDIT_ID" \
 && uv sync --locked --extra test --group build --group security --no-install-project --no-editable --no-build \
 && uv export --frozen --all-extras --all-groups --no-emit-project --output-file /tmp/requirements.txt \
 && /opt/test-venv/bin/pip-audit --require-hashes --disable-pip --strict -r /tmp/requirements.txt

FROM dependencies
LABEL org.opencontainers.image.source="https://github.com/caipe-io/caipe-sandbox" \
      org.opencontainers.image.title="CAIPE Sandbox"
COPY apps/portal/logging.json /etc/portal/logging.json
COPY --from=test /wheels/ /wheels/
RUN uv pip install --python /opt/venv/bin/python --no-index --no-deps /wheels/*.whl \
 && uv pip check --python /opt/venv/bin/python \
 && rm -rf /wheels /root/.cache /usr/local/bin/uv \
 && useradd --uid 10001 --create-home portal
ENV PATH="/opt/venv/bin:$PATH"
USER 10001
EXPOSE 8000
CMD ["uvicorn", "portal.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log", "--log-config", "/etc/portal/logging.json"]
