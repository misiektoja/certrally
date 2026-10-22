# The release image. GoReleaser builds the binaries and places one per platform in the build context,
# so this Dockerfile only copies it. distroless/static provides the CA certificates that HTTPS needs
# and runs as an unprivileged user.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:d62067879de890a1def9da0e7766b7d20810a5e5555cef8506b752437d7a3e88
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/certrally /usr/bin/certrally
ENTRYPOINT ["/usr/bin/certrally"]
