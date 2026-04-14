FROM eclipse-temurin:17-jdk-noble

RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl maven ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# OpenCode binary (pre-downloaded on host to avoid flaky GitHub access from Docker)
COPY opencode-linux-x64.tar.gz /tmp/opencode.tar.gz
RUN tar -xzf /tmp/opencode.tar.gz -C /usr/local/bin \
    && rm /tmp/opencode.tar.gz \
    && chmod +x /usr/local/bin/opencode

WORKDIR /workspace

# CodeGuard skills baked into the image; entrypoint conditionally copies them
COPY skills/ /opt/codeguard-skills/

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
