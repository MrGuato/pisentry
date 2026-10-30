# Demo host for the README recordings (scripts/demo/record.py). The agent
# binary and the scripts in this directory are mounted in at run time.
FROM python:3-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends jq \
 && rm -rf /var/lib/apt/lists/*
