# Build tooling only. The installed Client never needs this image.
FROM debian:12-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
RUN apt-get update && apt-get install -y --no-install-recommends python3 rpm libarchive-tools zstd dpkg-dev fakeroot && rm -rf /var/lib/apt/lists/*
