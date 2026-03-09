#!/usr/bin/env bash
set -Eeuo pipefail

CERT_DIR="/etc/ssl/localcerts"

echo "Self-Signed Certificate Generator"
echo "----------------------------------"

read -rp "Certificate name (default: selfsigned): " NAME
NAME="${NAME:-selfsigned}"

read -rp "Country (C) [US]: " COUNTRY
COUNTRY="${COUNTRY:-US}"

read -rp "State (ST) [NY]: " STATE
STATE="${STATE:-NY}"

read -rp "City (L) [NewYork]: " CITY
CITY="${CITY:-NewYork}"

read -rp "Organization (O) [Pace]: " ORG
ORG="${ORG:-Pace}"

read -rp "Organizational Unit (OU) [NECCDC]: " OU
OU="${OU:-NECCDC}"

read -rp "Common Name (CN) [$(hostname)]: " CN
CN="${CN:-$(hostname)}"

read -rp "Validity days [365]: " DAYS
DAYS="${DAYS:-365}"

KEY_BITS=4096

KEY_FILE="${CERT_DIR}/${NAME}.key"
CERT_FILE="${CERT_DIR}/${NAME}.crt"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root."
  exit 1
fi

mkdir -p "$CERT_DIR"
chmod 700 "$CERT_DIR"

SUBJECT="/C=${COUNTRY}/ST=${STATE}/L=${CITY}/O=${ORG}/OU=${OU}/CN=${CN}"

echo
echo "Generating certificate..."
echo "Subject: $SUBJECT"
echo

openssl req -x509 -nodes -newkey "rsa:${KEY_BITS}" \
  -keyout "$KEY_FILE" \
  -out "$CERT_FILE" \
  -days "$DAYS" \
  -subj "$SUBJECT"

chmod 600 "$KEY_FILE"
chmod 644 "$CERT_FILE"

echo
echo "Created:"
echo "  Key : $KEY_FILE"
echo "  Cert: $CERT_FILE"
echo

openssl x509 -in "$CERT_FILE" -noout -subject -dates -fingerprint -sha256