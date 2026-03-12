# Git-Flow Branching Model

| Branch | Purpose | Created from | Merges to |
|--------|---------|-------------|-----------|
| `master` | Production releases (tagged) | — | — |
| `develop` | Integration branch | — | — |
| `feature/*` | New features | `develop` | `develop` |
| `release/*` | Release prep (version bump, final fixes) | `develop` | `master` + `develop` |
| `hotfix/*` | Critical production fixes | `master` | `master` + `develop` |
| `fix/*` | Non-critical bug fixes | `develop` | `develop` |

## Release Process

```bash
git checkout -b release/v7.11.0 develop
# bump CMakeLists.txt VERSION, push, CI must pass
# PR to master → merge → tag
git tag v7.11.0 && git push origin v7.11.0
# → release.yml builds firmware + creates draft GitHub Release
# merge release branch back to develop
```

## CI/CD

- **ci.yml**: push to master, develop, feature/*, fix/*, release/*, hotfix/*
- **release.yml**: `v*` tag → build + hash + draft GitHub Release
