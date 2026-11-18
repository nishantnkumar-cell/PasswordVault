# The Secret Vault sync server on your own computer, in Docker (user guide
# chapter 16, docs/cloud-sync.md). The same server code as on Cloudflare,
# run by workerd, Cloudflare's open-source Workers runtime.
#
#   docker compose up -d --build        (with compose.yaml next to this file)

FROM node:22-bookworm-slim AS runtime
WORKDIR /build
COPY docker/package.json docker/package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund \
    && cp "$(find node_modules/@cloudflare -path '*/bin/workerd' -type f | head -n1)" /build/workerd \
    && /build/workerd --version

FROM ubuntu:24.04
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin vault-sync \
    && install -d -o vault-sync -g vault-sync -m 700 /data
COPY --from=runtime /build/workerd /usr/local/bin/workerd
COPY src/index.js /app/index.js
COPY docker/entrypoint.sh /usr/local/bin/vault-sync-server
RUN printf '#!/bin/sh\ncat /data/run/show\n' >/usr/local/bin/show && chmod 755 /usr/local/bin/show /usr/local/bin/vault-sync-server
USER vault-sync
VOLUME /data
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/vault-sync-server"]
