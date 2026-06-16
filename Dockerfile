# syntax=docker/dockerfile:1
ARG PYTHON_IMAGE=python:3.14-alpine3.24
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.11.19

FROM ${UV_IMAGE} AS uv
FROM ${PYTHON_IMAGE}

# Multiarch note: the runtime image is intended for linux/amd64 and linux/arm64,
# matching the platforms published by the pinned uv image.
COPY --from=uv /uv /uvx /bin/

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH"

RUN addgroup -g 1000 -S miniprint && adduser -S -D -H -u 1000 -G miniprint miniprint

COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project

COPY . .
RUN mkdir -p /app/log /app/uploads /tmp/miniprint \
    && chown -R miniprint:miniprint /app/log /app/uploads /tmp/miniprint

USER miniprint

EXPOSE 9100 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD MINIPRINT_HEALTHCHECK=1 /app/.venv/bin/python ./server.py --pjl-port 9100 --http-port 8080 || exit 1

CMD [ \
  "/app/.venv/bin/python", "./server.py", \
  "--bind", "0.0.0.0", \
  "--log-file", "log/miniprint.json", \
  "--timeout", "60", \
  "--max-connections", "16", \
  "--max-request-bytes", "65536", \
  "--max-job-bytes", "1048576", \
  "--max-virtual-file-bytes", "262144", \
  "--max-response-bytes", "131072" \
]
