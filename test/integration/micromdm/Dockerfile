# The SCEP server of micromdm/scep 2.3.0 for the SCEP integration tests.
# make test-integration-micromdm builds it as certrally-micromdm-scep. Extra arguments go to
# scepserver, such as -challenge.
FROM golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb

ARG SCEP_TAG=v2.3.0
ARG SCEP_COMMIT=8eb5412c850c98aaa83c3b96b2facae3710777d6
RUN apk add --no-cache git

RUN git clone --depth 1 --branch "$SCEP_TAG" https://github.com/micromdm/scep.git /src/scep \
 && test "$(git -C /src/scep rev-parse HEAD)" = "$SCEP_COMMIT"
WORKDIR /src/scep
RUN CGO_ENABLED=0 go build -o /usr/local/bin/scepserver ./cmd/scepserver

# The CA is created once in the image, so the tests can read its certificate before they start a
# server.
RUN scepserver ca -init -depot /depot -keySize 2048 -organization certrally-test

EXPOSE 8080
# -allowrenew 0 accepts a renewal at any time, not only in the last 14 days of a certificate.
ENTRYPOINT ["scepserver", "-depot", "/depot", "-port", "8080", "-allowrenew", "0", "-debug"]
