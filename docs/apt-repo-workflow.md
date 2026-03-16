# Reusable APT Pages Workflow

This repo provides a reusable GitHub Actions workflow to publish a signed APT repository to GitHub Pages.

## What it does

- Downloads .deb artifacts from the current workflow run.
- Builds APT repository metadata (pool/, dists/).
- Signs Release and InRelease files with a required GPG key.
- Publishes the repository to GitHub Pages.

## Requirements

- GitHub Pages enabled (Source: GitHub Actions).
- Secrets configured in the calling repo:
  - APT_GPG_PRIVATE_KEY (armored private key)
  - APT_GPG_PASSPHRASE (key passphrase)

## Usage

Add a job that calls the reusable workflow. Prefer pinning to a commit SHA.

```yaml
jobs:
  apt-repo:
    if: startsWith(github.ref, 'refs/tags/v')
    needs: [release]
    uses: tkjaer/etr/.github/workflows/reusable-apt-pages.yml@<commit-sha>
    with:
      package_name: etr
      suite: stable
      component: main
      architectures: amd64 arm64
      key_expiry_warn_days: 90
      key_expiry_fail_days: 14
    secrets:
      APT_GPG_PRIVATE_KEY: ${{ secrets.APT_GPG_PRIVATE_KEY }}
      APT_GPG_PASSPHRASE: ${{ secrets.APT_GPG_PASSPHRASE }}
```

## Notes

- The workflow fails closed if the signing key or passphrase is missing.
- The generated public key is published as <package_name>.gpg.key at the Pages root.
- The repo index page includes install instructions with signed-by.
