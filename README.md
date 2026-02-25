# loxws Package

Loxone Python Client

## Publishing to PyPI

Publishing is handled by GitHub Actions in `.github/workflows/publish-pypi.yml`.
Each commit push publishes automatically.

### One-time PyPI setup (Trusted Publishing)

1. Go to PyPI project settings for `loxws` and add a Trusted Publisher.
2. Use these values:
   - Owner: `grimbouk`
   - Repository: `loxws`
   - Workflow: `publish-pypi.yml`
   - Environment: `pypi`

### Release flow

1. Commit and push.
2. GitHub Actions computes the next `0.0.N` by checking existing PyPI releases (with local `_version.py` as fallback baseline).
3. The workflow updates `loxws/_version.py` for the build, builds distributions, and publishes to PyPI.

`setup.py` reads version from `loxws/_version.py` and supports CI override via `LOXWS_VERSION`.
