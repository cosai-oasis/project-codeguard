FROM python:3.13-slim@sha256:ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a AS default

# Model-controlled commands and the exporter use this named account. Compose
# uses root as the service identity so Inspect's injected tooling is root-owned.
RUN groupadd --gid 65532 nonroot \
    && useradd --uid 65532 --gid 65532 \
        --home-dir /workspace \
        --no-create-home \
        --no-log-init \
        --shell /usr/sbin/nologin \
        nonroot \
    && install -d -m 0555 \
        /usr/local/lib/python3.13/site-packages/codeguard_evals

ENV HOME=/workspace \
    LANG=C.UTF-8 \
    PATH=/usr/local/bin:/usr/bin:/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    TMPDIR=/tmp

# Python is pinned by the digest above, so site-packages is a known path.
COPY --chmod=0444 codeguard_evals/__init__.py \
    codeguard_evals/export_solution.py \
    codeguard_evals/safe_io.py \
    codeguard_evals/sandbox_protocol.py \
    /usr/local/lib/python3.13/site-packages/codeguard_evals/

WORKDIR /workspace
USER nonroot
