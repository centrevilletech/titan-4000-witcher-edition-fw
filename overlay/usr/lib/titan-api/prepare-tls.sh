#!/bin/sh
# Called only AFTER --prepare-boot-entropy. Publish a complete identity atomically.
set -eu
umask 077
tls=/mnt/titan-api/tls
[ -d "$tls" ] && [ ! -L "$tls" ] || exit 77
# True when directory $1 holds a certificate and the key it was made for.
usable() {
 for file in "$1/cert.pem" "$1/key.pem"; do
  [ -f "$file" ] && [ ! -L "$file" ] && [ -s "$file" ] || return 1
 done
 cert=$(openssl x509 -in "$1/cert.pem" -noout -pubkey 2> /dev/null) || return 1
 key=$(openssl pkey -in "$1/key.pem" -pubout 2> /dev/null) || return 1
 [ -n "$cert" ] && [ "$cert" = "$key" ]
}
# Keep the identity in use, legacy pair first as the launcher reads it:
# browsers have accepted it. Its modes are put right for the launcher's checks.
keep() {
 chown 0:0 "$1/cert.pem" "$1/key.pem"
 chmod 600 "$1/key.pem"
 chmod 644 "$1/cert.pem"
 exit 0
}
# One that fails a check (a file missing or empty, unreadable, or a key that is
# not the certificate's) would keep the web service off on every boot. It moves
# to $tls/broken, which keeps only the last one, and a new identity is made:
# browsers then ask once to accept the unit's new certificate.
broken=
if [ -e "$tls/cert.pem" ] || [ -e "$tls/key.pem" ] || [ -L "$tls/cert.pem" ] || [ -L "$tls/key.pem" ]; then
 if usable "$tls"; then keep "$tls"; fi
 broken="cert.pem key.pem"
fi
if [ -e "$tls/current" ] || [ -L "$tls/current" ]; then
 if [ -d "$tls/current" ] && [ ! -L "$tls/current" ] && usable "$tls/current"; then keep "$tls/current"; fi
 broken="$broken current"
fi
if [ -n "$broken" ]; then
 rm -rf "$tls/broken"
 mkdir "$tls/broken"
 for name in $broken; do
  if [ -e "$tls/$name" ] || [ -L "$tls/$name" ]; then mv "$tls/$name" "$tls/broken/"; fi
 done
 sync
 echo "The TLS identity failed its checks; it is kept in $tls/broken and a new one is made." >&2
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
