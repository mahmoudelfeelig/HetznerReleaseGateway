# Security policy

Please report vulnerabilities through GitHub's private security-advisory flow for this repository.
Do not include credentials, tokens, production data, or non-public infrastructure details in a public
issue.

## Trust boundary

Callers must reference the reusable workflow by its full reviewed commit SHA. The gateway checks that
immutable reference at runtime, verifies an exact successful push-triggered CI identity, rechecks the
source branch before every promotion, and uses short-lived GitHub OIDC credentials for publication.

Application manifests are treated as untrusted input even though they come from the exact source
commit. The parser rejects unknown fields, unsafe paths, foreign registry scopes, gateway-owned build
files, and runtime service metadata. Image destinations are derived from the application identifier.

The signed marker is only a release statement. A separate private policy remains authoritative for
which caller identities, gateway revisions, components, and source workflows are allowed. The public
gateway contains neither long-lived credentials nor private runtime policy.
