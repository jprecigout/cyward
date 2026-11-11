#!/usr/bin/env bash
# Vérification complète de Cyward : en-têtes de commentaires, compilation, clippy, tests,
# puis rejeu de bout en bout du pcap d'attaques simulées.
#
#   .claude/skills/verifier/check.sh            # vérification standard (~1 min)
#   .claude/skills/verifier/check.sh --docker   # + construction de l'image Docker
#
# Code de sortie 0 si tout passe ; sinon, s'arrête à la première étape en échec.
set -euo pipefail

# Racine du dépôt, quel que soit le dossier d'où le script est lancé.
cd "$(dirname "$0")/../../.."

# Alertes attendues au rejeu de examples/gen_attacks.rs : une sous-chaîne de titre par scénario.
# À mettre à jour quand un scénario est ajouté au générateur.
EXPECTED_TITLES=(
  "Balise périodique"
  "Force brute probable"
  "Scan de ports"
  "Balayage du port"
  "Tunnel DNS probable"
  "Volume sortant anormal"
)

step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
fail() { printf '\033[31mÉCHEC : %s\033[0m\n' "$1" >&2; exit 1; }

step "En-têtes de module (//!) dans chaque fichier Rust"
missing=$(for f in $(find src examples -name '*.rs'); do head -1 "$f" | grep -q '^//!' || echo "$f"; done)
[ -z "$missing" ] || fail "fichiers sans en-tête //! : $missing"
echo "ok"

step "Compilation"
cargo build --all-targets -q

step "Clippy (aucun avertissement toléré)"
cargo clippy --all-targets -q -- -D warnings

step "Tests unitaires"
cargo test -q 2>&1 | tail -3
cargo test -q >/dev/null 2>&1 || fail "des tests échouent (relancer cargo test pour le détail)"

step "Rejeu des attaques simulées"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cargo run -q --example gen_attacks -- "$tmp/attaques.pcap" >/dev/null
# NO_COLOR et redirection : sortie sans codes ANSI, comparable par texte.
report=$(NO_COLOR=1 cargo run -q -- replay "$tmp/attaques.pcap" 2>/dev/null)
echo "$report"
count=$(echo "$report" | sed -n 's/.*octets analysés, \([0-9]*\) alerte(s)/\1/p')
[ "$count" = "${#EXPECTED_TITLES[@]}" ] || fail "$count alerte(s) au lieu de ${#EXPECTED_TITLES[@]}"
# Recherche dans le bilan final uniquement (lignes « [Sévérité] … »), pas dans les journaux WARN.
summary=$(echo "$report" | grep '^\[' || true)
for t in "${EXPECTED_TITLES[@]}"; do
  echo "$summary" | grep -qF "$t" || fail "alerte attendue absente : « $t »"
done
echo "ok : ${#EXPECTED_TITLES[@]} alertes attendues, aucune en trop"

if [ "${1:-}" = "--docker" ]; then
  step "Image Docker"
  docker compose build -q cyward
  # Sortie capturée en entier : un `| head` couperait le flux et, avec pipefail, ferait échouer
  # le script dès que des journaux précèdent le bilan.
  docker_report=$(docker run --rm -e NO_COLOR=1 -v "$tmp:/data:ro" cyward:latest replay /data/attaques.pcap 2>/dev/null)
  docker_line=$(echo "$docker_report" | grep "octets analysés" || true)
  echo "$docker_line"
  docker_count=$(echo "$docker_line" | sed -n 's/.*octets analysés, \([0-9]*\) alerte(s)/\1/p')
  [ "$docker_count" = "${#EXPECTED_TITLES[@]}" ] || fail "image Docker : ${docker_count:-?} alerte(s) au lieu de ${#EXPECTED_TITLES[@]}"
fi

printf '\n\033[32mTout est vert.\033[0m\n'
