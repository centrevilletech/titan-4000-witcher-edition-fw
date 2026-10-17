#!/bin/sh
# Called only AFTER --prepare-boot-entropy. Publish a complete identity atomically.
set -eu
umask 077
tls=/mnt/titan-api/tls
[ -d "$tls" ] && [ ! -L "$tls" ] || exit 77
# Keep any previously installed identity intact, including incomplete legacy pairs.
if [ -e "$tls/cert.pem" ] || [ -e "$tls/key.pem" ]; then
 [ -f "$tls/cert.pem" ] && [ -f "$tls/key.pem" ] || exit 77
 exit 0
fi
if [ -e "$tls/current" ] || [ -L "$tls/current" ]; then
 [ -d "$tls/current" ] && [ ! -L "$tls/current" ] || exit 77
 [ -f "$tls/current/cert.pem" ] && [ -f "$tls/current/key.pem" ] || exit 77
 exit 0
fi
# Stock BusyBox has no mktemp applet. The kernel is already seeded here.
temporary=$tls/.new-$(openssl rand -hex 16)
mkdir "$temporary"
trap 'rm -rf "$temporary"' EXIT
trap 'exit 1' HUP INT TERM
# Explicit dates work without RTC, NTP, APN or Internet. The certificate is
# self-signed; browsers still ask the operator to accept the unit's identity.
cat > "$temporary/openssl.cnf" <<EOF
[req]
distinguished_name=dn
[dn]
[ca]
default_ca=local
[local]
database=$temporary/index
new_certs_dir=$temporary
serial=$temporary/serial
default_md=sha256
policy=policy
x509_extensions=server
[policy]
commonName=supplied
[server]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:witcher,IP:192.168.0.1,IP:10.1.1.1
EOF
: > "$temporary/index"
echo 01 > "$temporary/serial"
openssl req -config "$temporary/openssl.cnf" -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
 -pkeyopt ec_param_enc:named_curve -nodes \
 -keyout "$temporary/key.pem" -out "$temporary/request.pem" \
 -subj /CN=witcher > /dev/null 2>&1
openssl ca -config "$temporary/openssl.cnf" -batch -selfsign -notext \
 -keyfile "$temporary/key.pem" -in "$temporary/request.pem" \
 -out "$temporary/cert.pem" -startdate 19700101000000Z -enddate 20991231235959Z \
 > /dev/null 2>&1
# Only the completed key/certificate pair becomes the persistent identity.
rm -f "$temporary/openssl.cnf" "$temporary/request.pem" "$temporary/index"* \
 "$temporary/serial"* "$temporary/01.pem"
chmod 600 "$temporary/key.pem"
chmod 644 "$temporary/cert.pem"
sync
mv "$temporary" "$tls/current"
sync
