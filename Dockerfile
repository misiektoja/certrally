# The release image. GoReleaser builds the binaries and places one per platform in the build context,
# so this Dockerfile only copies it. distroless/static provides the CA certificates that HTTPS needs
# and runs as an unprivileged user.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/certrally /usr/bin/certrally
ENTRYPOINT ["/usr/bin/certrally"]
