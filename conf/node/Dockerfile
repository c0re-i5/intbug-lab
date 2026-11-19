# Pinned Node base (NODE_IMAGE=node@sha256:1314fb30…, :22-alpine → v22.23.5).
# Stdlib http2 only: no npm install. Certs are mounted at runtime from
# repo certs/ (same as Caddy/Envoy). The lab app is not separately hashed.
ARG NODE_IMAGE
FROM ${NODE_IMAGE}
WORKDIR /app
COPY server.js /app/server.js
COPY index.html /srv/index.html
EXPOSE 443
CMD ["node", "/app/server.js"]
