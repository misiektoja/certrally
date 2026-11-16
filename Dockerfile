# The release image. GoReleaser builds the binaries and places one per platform in the build context,
# so this Dockerfile only copies it. distroless/static provides the CA certificates that HTTPS needs
# and runs as an unprivileged user.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/certrally /usr/bin/certrally
ENTRYPOINT ["/usr/bin/certrally"]
