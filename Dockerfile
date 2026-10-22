# The release image. GoReleaser builds the binaries and places one per platform in the build context,
# so this Dockerfile only copies it. distroless/static provides the CA certificates that HTTPS needs
# and runs as an unprivileged user.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/certrally /usr/bin/certrally
ENTRYPOINT ["/usr/bin/certrally"]
