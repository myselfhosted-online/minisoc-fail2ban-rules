# Releasing a new version

Releases are generated automatically by GitHub Actions.

## Normal release process

1. Make and review the rule changes.
2. Update `CHANGELOG.md`.
3. Change the version in the root `VERSION` file.
4. Push the change to `main`.

Example:

```text
VERSION
1.0.1
```

A push that changes `VERSION` starts the **Publish release** workflow.

The workflow:

- validates the repository;
- reads and validates the semantic version;
- creates tag `v<version>`;
- builds ZIP and tar.gz archives;
- makes installer and validation scripts executable inside the archives;
- creates `SHA256SUMS.txt`;
- creates a GitHub Release;
- attaches the archives and checksums;
- generates GitHub release notes automatically.

## Manual run

The workflow also supports `workflow_dispatch`.

Open:

`Actions -> Publish release -> Run workflow`

If the tag for the current `VERSION` already exists, the workflow exits without publishing a duplicate release.

## Versioning

Use semantic versions:

```text
MAJOR.MINOR.PATCH
```

Examples:

- `1.0.0` — first stable public version;
- `1.0.1` — bug/rule correction;
- `1.1.0` — new backward-compatible rule families/features;
- `2.0.0` — incompatible layout or behavior changes.

## Security note

Do not put secrets, private tokens, cookies, credentials, or private production data into release assets.
