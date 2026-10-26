# The release image. GoReleaser builds the binaries and places one per platform in the build context,
# so this Dockerfile only copies it. distroless/static provides the CA certificates that HTTPS needs
# and runs as an unprivileged user.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/certrally /usr/bin/certrally
ENTRYPOINT ["/usr/bin/certrally"]
