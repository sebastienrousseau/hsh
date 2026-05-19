# Packaging

Templates for shipping the `hsh` CLI through every major OS package
ecosystem. The `release.yml` workflow (Phase 2) materialises these
into ready-to-ship artefacts on each tagged release.

## Targets

| Channel        | Template                          | Status   |
| -------------- | --------------------------------- | -------- |
| Docker         | `docker/Dockerfile`               | Template |
| Homebrew       | `homebrew/hsh.rb.template`        | Template |
| Debian (.deb)  | `debian/control.template`         | Template |
| Arch (AUR)     | `arch/PKGBUILD.template`          | Template |
| Scoop (Win)    | `scoop/hsh.json.template`         | Template |

The `release.yml` workflow does the substitution (`{{VERSION}}`,
`{{SHA256_*}}`, `{{ARCH}}`) and opens PRs / pushes commits to the
relevant tap / AUR repo on tag push.

## What's deferred

- **MSI / WIX** for Windows installer experience.
- **Flatpak** + **Snap** manifests.
- **Nix flake**.

Each is tracked under Phase 5 follow-up work in
[issue #144](https://github.com/sebastienrousseau/hsh/issues/144).

## Smoke-testing locally

```sh
# Docker
docker buildx build --platform=linux/amd64 -t hsh-test -f pkg/docker/Dockerfile .
docker run --rm -i hsh-test hash --algorithm scrypt <<<"correct-horse"

# Debian (requires dpkg-deb)
# … the release pipeline handles the .deb assembly.
```
