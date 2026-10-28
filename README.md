# Retool upgrade readiness script

Gathers the facts about a self-hosted Retool deployment into **one JSON file** that the
customer reviews and uploads to Retool. Read-only: it never changes the deployment.

## Run it

Download and run it on a machine that can reach your Retool deployment (`kubectl` or `docker`).

While this repository is internal, download with the GitHub CLI (`gh auth login` first):

```bash
gh api repos/tryretool/upgrade-readiness-script/contents/collect.py -H "Accept: application/vnd.github.raw" > collect.py
python3 collect.py -o retool-upgrade-report.json
```

Once the repository is public, `curl -fsSLO https://raw.githubusercontent.com/tryretool/upgrade-readiness-script/main/collect.py` does the same.

Open `retool-upgrade-report.json` and read it. It is the only thing the script produces, and it is
yours to review before you share it. Then upload it to the Upgrade Readiness Assistant, which returns
a step-by-step upgrade guide for your deployment.

**Requirements:** Python 3.7+ (standard library only), plus whichever applies:
- Kubernetes/Helm: `kubectl` pointed at the right cluster (`helm` optional, adds chart info)
- Docker / Docker Compose: `docker` with access to the daemon

The collector detects which one you have and asks only if it's unsure. It recognizes Retool by image
name or, for mirrored/renamed images, by the env vars every Retool backend has. The Retool version
comes from the backend image tag. If the image has no tag (e.g. a local build), the collector reads the
version from inside the running backend container instead (`version_source` in the report says which). If it finds nothing,
it prints what it checked and what it saw. It shows the active
`kubectl` context and asks you to confirm before collecting anything.

## What it collects
- Retool version, image tags, replicas, resource sizing, pod/container health
- Cluster/host info (Kubernetes version, nodes, ingress, storage; Docker/Compose versions)
- Helm release, chart history and user-supplied values (secrets redacted)
- Env var **names**; values only for a short allowlist of non-sensitive settings
- **Upgrade plan:** what the newest Retool version adds compared with what you run (new services and their CPU/memory),
  and whether your cluster/host has the room for it.
  - Kubernetes: renders the latest Helm chart locally with your own values and diffs it against your release.
    Your values are used in memory only; nothing from them is written to the report. Needs `helm` and network access to `charts.retool.com`.
  - Docker: compares your running services with the official compose file on GitHub, and checks the host's current usage.
  - Skip with `--skip-plan` (e.g. airgapped).
- Read-only counts/flags from the Retool database (apps, workflows, resource types, SSO,
  environments, embeds, ...). No row data.

**Not collected:** secrets, license key, hostnames/URLs, app contents, user data, logs.
Nothing is sent anywhere; the file is written locally for the customer to review.

## Useful flags

| Flag | Purpose |
|---|---|
| `--platform kubernetes\|docker` | skip auto-detection |
| `-n NAMESPACE` / `-r RELEASE` | Kubernetes namespace / Helm release |
| `--compose-project NAME` | Docker Compose project |
| `--postgres-target POD_OR_CONTAINER` | where to run the DB queries |
| `--skip-db` | collect nothing from the database |
| `--emit-sql FILE` | write the DB queries to a file to run yourself (external DB) |
| `--image-pattern REGEX` | only if you mirror/rename Retool images and auto-detection fails (default matches `tryretool/backend`) |
| `--read-version-from-container` | also record the version found inside the backend container, as a cross-check against the image tag |
| `--target-chart VERSION` | Helm chart to plan the upgrade to (default `latest`; charts are backward compatible) |
| `--skip-plan` | don't build the upgrade plan (it needs network access to charts.retool.com / GitHub) |
| `--customer-label TEXT` | optional free-text label to help match the report |
| `-y` / `--yes` | no confirmation prompts |

## Known limitations
- Tested against a Helm/Kubernetes deployment (Docker Desktop). The interactive prompts
  were not exercised in a live terminal by the author.
- The Docker / Docker Compose path was only tested with a stand-in container, **not a real
  Retool Compose stack**. Please try it and report what breaks.
- Database queries need the bundled Postgres pod/container (they run `psql` inside it).
  For an external DB (RDS, Cloud SQL, ...), use `--emit-sql` and run the file yourself.
- DB queries run as the Postgres user found in that container's env (read-only `SELECT`s).
