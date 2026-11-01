# Running EASM Agent on Kubernetes (GKE, AKS, EKS)

The agent ships as a container image, `ghcr.io/cyberjangle101/easm-agent:<version>`, for linux/amd64 and linux/arm64. Kubernetes manifests are in [`deploy/kubernetes`](../deploy/kubernetes).

## What to know first

- **One replica, always.**
  - Why: the agent keeps its data in SQLite with a single writer, locks its data folder, and runs its scheduler in-process.
  - So the manifests use a StatefulSet with `replicas: 1`. Never scale it up, and never use a Deployment with `RollingUpdate`: the new pod would wait for the old one's lock forever.
  - Availability: if a node fails, the pod is rescheduled once its disk reattaches, usually within a few minutes.
- **Block storage only**: GCE Persistent Disk, Azure Disk or EBS.
  - Not Filestore, Azure Files or NFS: SQLite's write-ahead log and the folder lock aren't reliable on network file systems.
  - To survive a zone outage, use a regional PD (GKE) or a ZRS disk (AKS).
- **Outbound internet access** is needed for public DNS resolvers, the intelligence sources, active checks of your hosts, SMTP and GitHub. Inbound traffic needs only the ingress controller.
- **Update by deploying a new image.** The image sets `EASM_MANAGED=1`, so the agent tells administrators when a release is out but never installs over itself. That change would be lost at the next restart.

## The image

- **What's in it:** built by the release workflow from the **signed release binaries**: no compiler, no shell, no package manager.
- **Base:** `distroless/static` (CA certificates only).
- **User:** runs as a non-root user (65532), with a read-only root file system.
- **Provenance:** every image carries **SLSA build provenance**. Check it before you deploy:

  ```bash
  gh attestation verify oci://ghcr.io/cyberjangle101/easm-agent:1.9.12 --repo cyberjangle101/cybersour-attack-surface-scanner
  ```

- **Pin the version:** pin a version tag, and ideally its digest (`…/easm-agent:1.9.12@sha256:…`). There's no `latest` tag on purpose.
- **Testing:** every release candidate's image goes through UAT before it can be promoted. The UAT run tests it hardened in Docker, then deploys these exact manifests to a kind cluster that enforces the restricted Pod Security Standard.
- **Running it standalone:** `docker run` serves HTTPS with a self-signed certificate on port 8443, with its data in the `/data` volume.

## Quick start

```bash
# 1. The key passphrase (at least 12 characters). Keep a copy offline: without it the data cannot be read.
openssl rand -base64 32 > passphrase.txt
kubectl create namespace easm
kubectl -n easm create secret generic easm-key-passphrase --from-file=passphrase=passphrase.txt
rm passphrase.txt   # after storing it in your password manager / vault

# 2. Deploy (set the image tag in deploy/kubernetes/kustomization.yaml first)
kubectl apply -k deploy/kubernetes
kubectl -n easm rollout status statefulset/easm-agent

# 3. The one-time code for creating the first administrator
kubectl -n easm exec easm-agent-0 -- /usr/local/bin/easm-agent -show-setup-code -data-dir /data/easm

# 4. Open the web interface (or add the ingress below) and create the administrator with that code
kubectl -n easm port-forward svc/easm-agent 8080:80   # then http://localhost:8080
```

The setup code is never written to the logs. Only someone allowed to `exec` into the pod can read it, and it stops working once the first administrator exists.

## The key passphrase

The database is encrypted, and the key file on the volume is locked with your passphrase. The pod reads it from a **file** (`EASM_KEY_PASSPHRASE_FILE=/run/secrets/easm/passphrase`), not from an environment variable, so it doesn't show up in `kubectl exec … env`. The quick start uses a Kubernetes Secret. In production, keep the passphrase in your cloud's secret manager and mount it with the Secret Store CSI driver.

**GKE: Secret Manager.** Enable Workload Identity and the Secret Manager add-on, then:

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata: {name: easm-passphrase, namespace: easm}
spec:
  provider: gke
  parameters:
    secrets: |
      - resourceName: "projects/PROJECT/secrets/easm-key-passphrase/versions/latest"
        path: "passphrase"
```

Give the Kubernetes service account `easm/easm-agent` the `roles/secretmanager.secretAccessor` role on that secret. In `statefulset.yaml`, replace the `passphrase` volume with:

```yaml
- name: passphrase
  csi: {driver: secrets-store-gke.csi.k8s.io, readOnly: true, volumeAttributes: {secretProviderClass: easm-passphrase}}
```

**AKS: Key Vault.** Enable the Key Vault provider add-on and Azure Workload Identity:

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata: {name: easm-passphrase, namespace: easm}
spec:
  provider: azure
  parameters:
    clientID: "<workload identity client id>"
    keyvaultName: "<vault>"
    tenantId: "<tenant id>"
    objects: |
      array:
        - |
          objectName: easm-key-passphrase
          objectType: secret
          objectAlias: passphrase
```

Annotate the service account with `azure.workload.identity/client-id`, label the pod `azure.workload.identity/use: "true"`, and replace the `passphrase` volume with `csi: {driver: secrets-store.csi.k8s.io, readOnly: true, volumeAttributes: {secretProviderClass: easm-passphrase}}`.

## Storage

The claim asks for 10 GiB from the default storage class. For zone resilience, set `storageClassName` in `statefulset.yaml` to a class like one of these:

```yaml
# GKE: regional persistent disk
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata: {name: regional-pd}
provisioner: pd.csi.storage.gke.io
parameters: {type: pd-balanced, replication-type: regional-pd}
volumeBindingMode: WaitForFirstConsumer
allowVolumeExpansion: true
---
# AKS: zone-redundant disk
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata: {name: managed-csi-zrs}
provisioner: disk.csi.azure.com
parameters: {skuName: Premium_ZRS}
volumeBindingMode: WaitForFirstConsumer
allowVolumeExpansion: true
```

**Backups:**
- Use **Settings → Backup** in the app. It can run on a schedule and keep copies in the data folder. Copy them off the volume with a CronJob or your backup tool.
- Disk snapshots are crash-consistent and usually restore. The app's backup is the one guaranteed to be consistent, and it includes the key.

## Web access and TLS

- **Default:** inside the cluster the pod serves plain HTTP on port 8080, and TLS ends at your ingress or gateway (`plain_http: true`, `secure_cookies: true` in the ConfigMap). The NetworkPolicy lets only the ingress controller reach the pod. Change its namespace label to match your controller.
- **Example:** [`deploy/kubernetes/examples/ingress.yaml`](../deploy/kubernetes/examples/ingress.yaml) shows ingress-nginx with cert-manager.
- **Single sign-on in front:** consider **IAP** (GKE, with a Gateway or Ingress) or **Entra ID / App Proxy** (AKS). The agent keeps its own sign-in and 2FA behind it.
- **TLS all the way to the pod:** remove `plain_http`, mount a certificate Secret, and set `tls_cert` / `tls_key` in the ConfigMap.

## Outbound traffic and your public IP

Scans leave from the cluster's NAT address, so give the agent a **dedicated static egress IP**. Otherwise the targets' intrusion detection, and services like SANS ISC, may flag an address your other workloads share. Tell the owners of the targets about that IP.

- **GKE:** a node pool for the agent (taint and toleration, or a node selector) with **Cloud NAT** on a reserved static address.
- **AKS:** a node pool in its own subnet with a **NAT Gateway** and a static public IP.

The NetworkPolicy allows internet egress but blocks the cluster's private ranges and the cloud metadata server. The agent also refuses to probe non-public addresses itself.

## Updating

1. Wait for a release (the agent's System health page announces it).
2. Change `newTag` in `deploy/kubernetes/kustomization.yaml`, then run `kubectl apply -k deploy/kubernetes`.
3. The StatefulSet replaces the pod. The new version opens the same volume, and it may upgrade the database on first start, so take a backup first.

Going back means deploying the previous tag. A database that a newer version has already upgraded may need the backup from before the update.

## Operations

- **Logs:** JSON on stdout (`kubectl -n easm logs easm-agent-0`), picked up by Cloud Logging or Azure Monitor.
- **Health:** `/healthz` backs the startup, liveness and readiness probes. Connector health is on the **System health** page.
- **Restart:** `kubectl -n easm delete pod easm-agent-0`. A running scan stops, and the next scheduled scan picks it up again.
- **Graceful stop:** SIGTERM shuts the web server down cleanly. `terminationGracePeriodSeconds` is 60.
- **Lost administrator password:**
  - **If another administrator exists:** reset it in **Users**.
  - **If you're the only administrator:** `-reset-password` needs the data folder to itself, so it can't run inside the live pod. Stop the agent, run a one-off pod on the same volume, then start the agent again:

    ```bash
    kubectl -n easm scale statefulset/easm-agent --replicas=0
    kubectl -n easm run easm-reset --rm -it --restart=Never --image=<same image> \
      --overrides='{"spec":{"securityContext":{"runAsNonRoot":true,"runAsUser":65532,"fsGroup":65532,"seccompProfile":{"type":"RuntimeDefault"}},"containers":[{"name":"easm-reset","image":"<same image>","stdin":true,"tty":true,"args":["-reset-password","<user>","-data-dir","/data/easm"],"env":[{"name":"EASM_KEY_PASSPHRASE_FILE","value":"/run/secrets/easm/passphrase"}],"securityContext":{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]}},"volumeMounts":[{"name":"data","mountPath":"/data"},{"name":"passphrase","mountPath":"/run/secrets/easm"}]}],"volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"data-easm-agent-0"}},{"name":"passphrase","secret":{"secretName":"easm-key-passphrase","defaultMode":288}}]}}'
    kubectl -n easm scale statefulset/easm-agent --replicas=1
    ```
- **Resources:** requests are 100m CPU and 256 Mi, with a 1 Gi memory limit. Raise the limit for very large estates.

## Not available in the container

- **Screenshots:** the image has no Chromium, so the feature reports itself as unavailable.
- **Windows-only features:** DPAPI key protection, the tray icon and `-service install`.
- **High availability with more replicas:** see "One replica, always" above.
