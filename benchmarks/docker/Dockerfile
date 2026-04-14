FROM eclipse-temurin:17-jdk-noble

RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl maven ca-certificates \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs \
    && npm install -g @opencode-ai/opencode \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# CodeGuard skills baked into the image; entrypoint conditionally copies them
COPY skills/ /opt/codeguard-skills/

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
