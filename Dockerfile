# Dockerfile for the NAC distributed evaluation services.
# Produces one image used by: oauth_server, bench-workers, and the hub client.
# Keeps dependencies minimal — only what's needed for HTTP + crypto + Redis.

FROM python:3.10-slim

WORKDIR /app

# Install only the subset of requirements.txt needed for the benchmark services
# (skip MCP, anthropic — not used in the distributed HTTP-only path)
RUN pip install --no-cache-dir \
    fastapi==0.115.0 \
    uvicorn==0.30.0 \
    httpx==0.27.0 \
    pyjwt==2.9.0 \
    cryptography==43.0.0 \
    redis>=5.0.0 \
    python-multipart==0.0.12

# Copy the core modules needed by all services
COPY nac_common.py audit_log.py oauth_server.py \
     service_bench_oauth.py service_bench_worker.py ./

# Shared signing-key volume is mounted at /app/.nac_keys by docker-compose
ENV NAC_KEY_DIR=/app/.nac_keys

# Default command is overridden in docker-compose for each service
CMD ["python", "-c", "print('NAC service image — override the command in docker-compose')"]
