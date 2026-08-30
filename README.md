# Hetzner Release Gateway

This repository is the deliberately small public half of an image-release system. A caller
provides an exact successful source commit, and the gateway independently verifies the triggering
GitHub Actions run and every workflow required by that commit's release manifest. It then publishes
immutable component images and a schema-v2 release marker using a short-lived GitHub OIDC identity.
Component images are normalized into a local OCI layout, then uploaded through the registry's
resumable API in bounded chunks so an interrupted request resumes without restarting a large layer.
Each component manifest carries gateway-owned provenance that binds the canonical release plan,
source, component, strategy, and exact gateway commit. A retry may reuse an existing source-SHA tag
only after a read-only HEAD/GET verifies that complete provenance and the manifest digest; legacy or
mismatched tags fail closed and are never overwritten.

The gateway does not contain an application inventory or any runtime orchestration policy. The
private controller independently decides whether a marker is authorized and how its named image
components are used.

## Application manifest

Every application owns one manifest at `.github/hetzner-release.json`. The manifest is read from the
exact source SHA being released. It contains source identity, CI requirements, registry scope, and
build metadata only.

```json
{
  "version": 1,
  "id": "example-app",
  "source": {
    "repository": "owner/example-app",
    "default_branch": "main",
    "required_workflows": ["CI"]
  },
  "registry": {
    "host": "registry.elfeel.me",
    "image_namespace": "apps/example-app",
    "release_repository": "releases/example-app"
  },
  "release": {
    "strategy": "source-build",
    "components": [
      {
        "name": "web",
        "context": ".",
        "dockerfile": "Dockerfile"
      }
    ]
  }
}
```

Source builds may additionally specify a build target and non-secret string build arguments.
Dockerfiles must belong to the application checkout. An artifact release instead declares one
artifact name containing exactly one `{sha}` and one `{attempt}`, plus one SHA-bound local image name
per component. The gateway resolves one nonexpired artifact for the selected successful attempt,
downloads it by immutable artifact ID, verifies GitHub's digest, and safely extracts it. Unknown
fields fail closed.

## Caller workflow

The application keeps a small `workflow_run` caller. Replace the placeholder below with the exact
40-character commit that was reviewed in this repository. Branch and tag references are rejected by
the reusable workflow.

```yaml
name: Production release

on:
  workflow_run:
    workflows: [CI]
    types: [completed]

permissions:
  actions: read
  contents: read
  id-token: write

jobs:
  release:
    if: github.event.workflow_run.conclusion == 'success'
    uses: mahmoudelfeelig/HetznerReleaseGateway/.github/workflows/release.yml@0123456789abcdef0123456789abcdef01234567
    with:
      app: example-app
      source_sha: ${{ github.event.workflow_run.head_sha }}
      ci_run_id: ${{ github.event.workflow_run.id }}
```

No repository secret is passed to the gateway. The caller's scoped GitHub token is used only to
verify its own CI evidence and retrieve its own artifact when required.

## Release marker

The marker has schema version 2. It records the application and source identities, the exact gateway
repository, workflow path and commit, required CI run evidence, and a mapping from component names to
immutable OCI references. Artifact releases also record the exact run attempt, artifact ID, name,
digest, size, and expected payload paths; source builds record a null artifact. The marker contains
no runtime service mapping. Its timestamp comes from immutable completed-CI evidence, and the gateway
constructs the OCI config, manifest, and `/release.json` layer deterministically rather than relying
on Docker's legacy manifest format. The source-SHA marker remains create-only. After one final release
plan comparison, the in-memory OIDC registry client may update only the same release repository's
literal `production` tag and verifies the resulting digest, media type, length, hash, and bytes.

The per-application workflow concurrency group remains active through receipt completion. This is a
required serialization boundary for the mutable production pointer: the Registry V2 manifest PUT has
no compare-and-swap primitive. If a transient write has an ambiguous outcome, the gateway accepts the
exact target, retries only while the previously observed pointer is unchanged, and fails if it sees a
third digest.

The gateway waits for a signed schema-v2 terminal receipt. A receipt has exactly eight fields:
version, application, source SHA, release reference, terminal status, completion time, rollback
scope, and whether persistent state was restored. The final two fields prevent a runtime-only
rollback from being mistaken for a database or content restore. Extra operational evidence is
deliberately rejected at this public boundary.

## Local verification

Run the same checks used by public CI:

```text
python -m compileall -q scripts tests
python -m unittest discover -s tests -v
```

The project uses only the Python standard library. Docker, OpenSSL, and network access are needed only
by an actual GitHub-hosted release run.
