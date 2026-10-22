# Verify a download

Every [release](https://github.com/misiektoja/certrally/releases) is signed and carries build provenance and SBOMs. The commands below check version 0.1.0. Replace the version for other releases.

`checksums.txt` lists the SHA-256 digest of every archive. The release workflow signs it with a keyless cosign signature. Check the signature, then the archives:

```bash
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity https://github.com/misiektoja/certrally/.github/workflows/release.yml@refs/tags/v0.1.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
sha256sum --check --ignore-missing checksums.txt
```

Archives and images also carry GitHub build provenance:

```bash
gh attestation verify certrally_0.1.0_linux_amd64.tar.gz --repo misiektoja/certrally
gh attestation verify oci://ghcr.io/misiektoja/certrally:0.1.0 --repo misiektoja/certrally
```

The release also carries the archive provenance as `certrally_0.1.0.intoto.jsonl`, for `gh attestation verify --bundle` without access to GitHub's API.

Each archive has an SPDX SBOM next to it, named after the archive with `.sbom.json` appended. The image carries its SBOM as an attestation.
