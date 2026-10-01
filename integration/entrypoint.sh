#!/bin/sh
set -eu
umask 077
mkdir -p /test-artifacts
openssl req -x509 -newkey rsa:2048 -nodes -days 7 -subj /CN=localhost \
  -addext subjectAltName=DNS:localhost,IP:127.0.0.1 \
  -addext extendedKeyUsage=serverAuth \
  -keyout /test-artifacts/server.key -out /test-artifacts/server.crt >/dev/null 2>&1
python3 -c 'import secrets,pathlib; pathlib.Path("/test-artifacts/password.txt").write_text(secrets.token_urlsafe(24))'
test_password=$(cat /test-artifacts/password.txt)
./vpnserver start >/dev/null
trap './vpnserver stop >/dev/null 2>&1 || true' EXIT INT TERM
cmd() { /opt/vpncmd/vpncmd localhost:5555 /SERVER /PASSWORD: /CMD "$@" >/dev/null; }
hubcmd() { /opt/vpncmd/vpncmd localhost:5555 /SERVER /HUB:TEST /PASSWORD: /CMD "$@" >/dev/null; }
n=0
until cmd ServerInfoGet; do n=$((n + 1)); test "$n" -lt 30; sleep 1; done
cmd ServerCertSet /LOADCERT:/test-artifacts/server.crt /LOADKEY:/test-artifacts/server.key
cmd HubCreate TEST /PASSWORD:
cmd HubCreate NODHCP /PASSWORD:
/opt/vpncmd/vpncmd localhost:5555 /SERVER /HUB:NODHCP /PASSWORD: /CMD UserCreate test /GROUP:none /REALNAME:none /NOTE:none >/dev/null
/opt/vpncmd/vpncmd localhost:5555 /SERVER /HUB:NODHCP /PASSWORD: /CMD UserPasswordSet test "/PASSWORD:$test_password" >/dev/null
hubcmd UserCreate test /GROUP:none /REALNAME:none /NOTE:none
hubcmd UserPasswordSet test "/PASSWORD:$test_password"
hubcmd SecureNatEnable
hubcmd UserCreate guest /GROUP:none /REALNAME:none /NOTE:none
hubcmd UserAnonymousSet guest
openssl x509 -in /test-artifacts/server.crt -outform DER | openssl dgst -sha256 -r | cut -d' ' -f1 > /test-artifacts/pin.txt
printf 'Stock Stable server ready on localhost:5555; test profile TEST/test. Credentials and certificate are in .local (test-only).\n'
while true; do sleep 1; done
