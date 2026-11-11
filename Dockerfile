# syntax=docker/dockerfile:1

# ---- Compilation ----
FROM rust:1.97-slim-trixie AS build
WORKDIR /src

# Dépendances d'abord : cette couche reste en cache tant que Cargo.toml et Cargo.lock ne changent pas.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src

# Le dashboard (assets/) est embarqué dans le binaire à la compilation.
COPY src src
COPY assets assets
RUN touch src/main.rs && cargo build --release --locked

# ---- Exécution ----
FROM debian:trixie-slim

LABEL org.opencontainers.image.title="cyward" \
      org.opencontainers.image.licenses="Apache-2.0"

# journalctl (paquet systemd) sert à lire le journal de l'hôte monté dans le conteneur.
RUN apt-get update \
    && apt-get install -y --no-install-recommends systemd ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/target/release/cyward /usr/local/bin/cyward
COPY docker/cyward.toml /etc/cyward/cyward.toml

EXPOSE 8080
ENTRYPOINT ["cyward", "-c", "/etc/cyward/cyward.toml"]
CMD ["run"]
