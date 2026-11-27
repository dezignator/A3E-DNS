# A3E-DNS deployment

Docker images and compose stack for the A3E-DNS system. The three
images correspond to the three languages: the Python pipeline, the Go
resolver, and the Rust core (build-stage only).

## Images

| Image | Purpose | Size |
|-------|---------|------|
| `a3e/python-pipeline` | Python pipeline, Rust extension pre-built | ~380 MB |
| `a3e/go-resolver` | Go resolver, distroless runtime | ~12 MB |
| `a3e/rust-core` | Rust core, build-stage only | n/a |

## Bringing the stack up

```bash
docker compose -f docker/compose.yaml up --build
