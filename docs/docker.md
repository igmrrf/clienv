# Docker Containerization & Image Deployment Guide

This guide covers building lightweight Docker container images for `bsec`, publishing them to **Docker Hub** and **GitHub Container Registry (`ghcr.io`)**, and orchestrating local dev stacks with `docker compose`.

---

## 🛠 Multi-Stage `Dockerfile`

Create a multi-stage `Dockerfile` in the repository root:

```dockerfile
# --- Build Stage ---
FROM rust:1.85-alpine as builder

RUN apk add --no-libc-dev musl-dev gcc pkgconfig openssl-dev

WORKDIR /usr/src/bsec
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --target x86_64-unknown-linux-musl

# --- Final Runtime Stage ---
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /usr/src/bsec/target/x86_64-unknown-linux-musl/release/bsec /usr/local/bin/bsec

ENTRYPOINT ["bsec"]
CMD ["--help"]
```

---

## 🐳 Local Docker Building & Testing

### 1. Build Image

```bash
docker build -t bsec:latest .
```

### 2. Run Container CLI Commands

```bash
# Display version
docker run --rm bsec:latest --version

# Run bsec mounted with local workspace
docker run --rm -v $(pwd):/app -w /app bsec:latest status
```

---

## 🚀 Publishing Container Images

### 1. Publish to Docker Hub

```bash
docker login -u <DOCKER_HUB_USERNAME>
docker tag bsec:latest <DOCKER_HUB_USERNAME>/bsec:v0.1.0
docker tag bsec:latest <DOCKER_HUB_USERNAME>/bsec:latest

docker push <DOCKER_HUB_USERNAME>/bsec:v0.1.0
docker push <DOCKER_HUB_USERNAME>/bsec:latest
```

### 2. Publish to GitHub Container Registry (`ghcr.io`)

```bash
echo ${{ secrets.GITHUB_TOKEN }} | docker login ghcr.io -u igmrrf --password-stdin

docker tag bsec:latest ghcr.io/igmrrf/bsec:v0.1.0
docker tag bsec:latest ghcr.io/igmrrf/bsec:latest

docker push ghcr.io/igmrrf/bsec:v0.1.0
docker push ghcr.io/igmrrf/bsec:latest
```

---

## 🤖 GitHub Actions Workflow (`.github/workflows/docker.yml`)

```yaml
name: Publish Docker Image

on:
  release:
    types: [published]

jobs:
  docker:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and Push GHCR Image
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: |
            ghcr.io/igmrrf/bsec:${{ github.ref_name }}
            ghcr.io/igmrrf/bsec:latest
```

---

## 📦 Local Stack Orchestration (`docker-compose.yml`)

For local testing with an Anvil EVM node and IPFS gateway:

```bash
docker compose up -d
```
