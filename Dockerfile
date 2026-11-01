# EASM Agent container image.
#
# Built by the Release workflow from the signed release binaries in dist/ (verified against
# SHA256SUMS.sig before the build), so the image holds exactly the program users download:
# no compiler, no shell, no package manager. See docs/KUBERNETES.md.
#
#   docker buildx build --platform linux/amd64,linux/arm64 --build-arg VERSION=X.Y.Z .
#
# distroless/static: CA certificates and a nonroot user (65532), nothing else. Pinned by digest;
# Dependabot (docker) keeps it current.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG TARGETARCH
ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.title="EASM Agent" \
      org.opencontainers.image.description="External attack surface monitoring agent" \
      org.opencontainers.image.source="https://github.com/cyberjangle101/cybersour-attack-surface-scanner" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

COPY --chmod=0555 dist/easm-agent-linux-${TARGETARCH} /usr/local/bin/easm-agent
# The volume mount point, owned by the runtime user so a fresh Docker volume is writable.
# The agent keeps its data in /data/easm, a folder it creates and restricts itself.
COPY --chown=65532:65532 --chmod=0750 deploy/container/data/ /data/

# The image sets the version, so the agent reports new releases but never installs over itself.
ENV EASM_MANAGED=1

USER 65532:65532
EXPOSE 8443
VOLUME ["/data"]
ENTRYPOINT ["/usr/local/bin/easm-agent"]
# Standalone default: HTTPS with an automatic self-signed certificate. On Kubernetes the
# manifests pass -config instead (plain HTTP behind a TLS-terminating ingress).
CMD ["-data-dir", "/data/easm", "-listen", "0.0.0.0:8443", "-no-browser"]
