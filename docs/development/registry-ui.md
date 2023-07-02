
```bash
skopeo login --tls-verify=false 127.0.0.1:5000
skopeo copy --dest-tls-verify=false docker://arm32v6/python:3.12-rc-alpine docker://127.0.0.1:5000/arm32v6/python:3.12-rc-alpine
skopeo copy --dest-tls-verify=false --override-os=linux docker://python:3.12-rc-alpine docker://127.0.0.1:5000/python:3.12-rc-alpine

skopeo copy --dest-tls-verify=false --override-os=linux docker://devopstales/registry-imega-test:1.0 docker://127.0.0.1:5000/registry-imega-test:1.0
skopeo copy --dest-tls-verify=false --override-os=linux docker://devopstales/registry-imega-test:2.0 docker://127.0.0.1:5000/registry-imega-test:2.0
skopeo copy --dest-tls-verify=false --override-os=linux docker://devopstales/registry-imega-test:3.0 docker://127.0.0.1:5000/registry-imega-test:3.0
skopeo copy --dest-tls-verify=false --override-os=linux docker://devopstales/registry-imega-test:3.0 docker://127.0.0.1:5000/registry-imega-test:test

oras login --plain-http 127.0.0.1:5000
oras copy --to-plain-http ghcr.io/aquasecurity/trivy-db:2 127.0.0.1:5000/trivy-db:2
oras copy --to-plain-http ghcr.io/aquasecurity/trivy-java-db:1 127.0.0.1:5000/trivy-java-db:1

helm pull oci://registry-1.docker.io/bitnamicharts/redis --version 17.9.5
helm push redis-17.9.5.tgz OCI://127.0.0.1:5000/helm-charts

# https://github.com/helm/helm/issues/6141

COSIGN_EXPERIMENTAL=1 cosign sign 127.0.0.1:5000/registry-imega-test:1.0
COSIGN_EXPERIMENTAL=1 cosign verify 127.0.0.1:5000/registry-imega-test:1.0

trivy i --format cosign-vuln 127.0.0.1:5000/registry-imega-test:1.0 > image.sbom
cosign attach sbom --sbom image.sbom 127.0.0.1:5000/registry-imega-test:1.0

COSIGN_EXPERIMENTAL=1 cosign sign --attachment sbom 127.0.0.1:5000/registry-imega-test:1.0
```
