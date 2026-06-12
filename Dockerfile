# node:22-slim (glibc) on purpose: better-sqlite3 ships prebuilt binaries
# for it. On alpine (musl) it compiles from source and you'd need
# python3/make/g++ in the image.
FROM node:22-slim

ENV NODE_ENV=production
WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev

COPY pgp-oidc-idp.mjs ./

# SQLite lives on a volume so the JWT key, sessions, and users survive
# image rebuilds, not just restarts.
VOLUME ["/data"]
ENV DB_PATH=/data/idp.sqlite

# Anything but 3000, per the host's existing service.
ENV PORT=3100
EXPOSE 3100

# Container runs as non-root; /data is chowned at build time, and the
# compose file mounts a host dir over it (chown that dir to 1000:1000).
RUN mkdir -p /data && chown node:node /data /app
USER node

CMD ["node", "pgp-oidc-idp.mjs"]
