# nghttpd (nghttp2 reference HTTP/2 server) on a digest-pinned debian base.
# NOTE: the apt layer (nghttp2-server) is NOT itself digest-pinned; only the
# base image is. Documented in README under reproducibility limits.
ARG DEBIAN_IMAGE
FROM ${DEBIAN_IMAGE}
RUN apt-get update \
 && apt-get install -y --no-install-recommends nghttp2-server openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY index.html /srv/index.html
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 443
ENTRYPOINT ["/entrypoint.sh"]
