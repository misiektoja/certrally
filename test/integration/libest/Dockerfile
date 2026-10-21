# The example EST server of Cisco libest 3.2.0 for the EST integration tests.
# make test-integration-libest builds it as certrally-libest. Extra arguments go to estserver.
# libest 3.2.0 needs OpenSSL 1.1.1, which Ubuntu 20.04 provides.
FROM ubuntu:20.04@sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214

ARG LIBEST_TAG=r3.2.0
ARG LIBEST_COMMIT=4ca02c6d7540f2b1bcea278a4fbe373daac7103b
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends build-essential ca-certificates git libssl-dev openssl

RUN git clone --depth 1 --branch "$LIBEST_TAG" https://github.com/cisco/libest.git /src/libest \
 && test "$(git -C /src/libest rev-parse HEAD)" = "$LIBEST_COMMIT"
WORKDIR /src/libest
# libest stores getopt results in a char, which is unsigned on arm64 and never matches -1.
RUN ./configure --prefix=/usr/local/est CFLAGS="-O2 -fsigned-char" && make -j"$(nproc)" && make install

WORKDIR /src/libest/example/server
# createCA.sh waits for a key press before it creates the CAs.
RUN echo | bash ./createCA.sh > /tmp/createCA.log 2>&1 && test -s estCA/cacert.crt

# The example server certificate names 127.0.0.1 only in its CN, which Go clients do not accept,
# so it is replaced with one that carries the address as a subjectAltName.
RUN printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n' > /tmp/san.ext \
 && openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj /CN=127.0.0.1 \
    -keyout /tmp/server.key -out /tmp/server.csr \
 && openssl x509 -req -sha256 -days 365 -in /tmp/server.csr -CA estCA/cacert.crt -CAkey estCA/private/cakey.pem \
    -CAcreateserial -extfile /tmp/san.ext -out /tmp/server.crt \
 && cat /tmp/server.crt /tmp/server.key > estCA/private/estservercertandkey.pem

# A TLS-SRP verifier for the test user srpuser with the password srppwd. The passwd.srpv that comes
# with libest uses a 1536-bit group, which certrally refuses, so this one uses 2048 bits.
RUN touch certrally.srpv && openssl srp -srpvfile certrally.srpv -add -gn 2048 -passout pass:srppwd srpuser

ENV EST_TRUSTED_CERTS=./trustedcerts.crt
ENV EST_CACERTS_RESP=./estCA/cacert.crt
ENV EST_OPENSSL_CACONFIG=./estExampleCA.cnf
ENV LD_LIBRARY_PATH=/usr/local/est/lib
EXPOSE 8085
# The server accepts the user estuser with the password estpwd, which the example code sets.
ENTRYPOINT ["./estserver", "-c", "estCA/private/estservercertandkey.pem", "-k", "estCA/private/estservercertandkey.pem", "-r", "estrealm", "-p", "8085", "-v"]
