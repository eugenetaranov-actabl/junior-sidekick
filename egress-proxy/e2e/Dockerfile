# Runtime-only image for the egress-proxy end-to-end test.
# Build context is the repo root; the sandbox rootfs image (tag: sidekick-sandbox-rootfs) and the
# service dist (sandbox-service/build/install/sandbox-service) must exist beforehand - see run.sh.
FROM eclipse-temurin:25-jre

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bubblewrap \
        curl \
        ca-certificates \
        nftables \
        iproute2 \
        procps \
    && rm -rf /var/lib/apt/lists/*

# Host-side dirs referenced by sandbox.allowed-source-prefixes (validated to exist at startup) and
# the proxy state dir. Mount sources for requests would live under these; the demo sends none.
RUN mkdir -p /work /data /app/egress-state

# JDK 25: let Netty use native/Unsafe paths without warnings.
ENV JAVA_OPTS="--enable-native-access=ALL-UNNAMED --sun-misc-unsafe-memory-access=allow"

# The filesystem that runs inside bwrap (has bash, curl, ca-certificates).
COPY --from=sidekick-sandbox-rootfs / /rootfs

# The Ktor sandbox-service, built on the host with :sandbox-service:installDist.
COPY sandbox-service/build/install/sandbox-service /app/sandbox-service
COPY egress-proxy/e2e/application.conf /app/application.conf

EXPOSE 7171
CMD ["/app/sandbox-service/bin/sandbox-service", "-config=/app/application.conf"]
