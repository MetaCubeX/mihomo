#!/bin/sh
set -eu

active_marker=/tmp/openvpn-active-testuser
case "${0##*/}" in
openvpn-active-connect)
  mkdir "$active_marker" 2>/dev/null || true
  if [ -n "${CONNECTION_COUNT_FILE:-}" ]; then
    connection_count=$(cat "$CONNECTION_COUNT_FILE")
    printf '%d\n' "$((connection_count + 1))" >"$CONNECTION_COUNT_FILE"
  fi
  exit 0
  ;;
openvpn-active-disconnect)
  (
    sleep "${ACTIVE_RELEASE_DELAY:-0}"
    rmdir "$active_marker" 2>/dev/null || true
  ) &
  exit 0
  ;;
esac

case "${1:-}" in
bootstrap)
  if [ ! -s /state/ca.crt ] || \
    ! openssl x509 -in /state/server.crt -noout -text 2>/dev/null | grep -q 'DNS:openvpn-fault'; then
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 \
      -keyout /state/ca.key -out /state/ca.crt -days 2 \
      -subj /CN=mihomo-openvpn-rekey-test-ca >/dev/null 2>&1
    openssl req -newkey rsa:2048 -nodes -sha256 \
      -keyout /state/server.key -out /state/server.csr \
      -subj /CN=openvpn >/dev/null 2>&1
    printf '%s\n' \
      'basicConstraints=CA:FALSE' \
      'keyUsage=digitalSignature,keyEncipherment' \
      'extendedKeyUsage=serverAuth' \
      'subjectAltName=DNS:openvpn-static,DNS:openvpn-token,DNS:openvpn-fault' >/state/server.ext
    openssl x509 -req -sha256 -days 2 \
      -in /state/server.csr -CA /state/ca.crt -CAkey /state/ca.key \
      -CAcreateserial -extfile /state/server.ext \
      -out /state/server.crt >/dev/null 2>&1
  fi

  write_client_config() {
    config_name=$1
    server_name=$2
    disable_auth_token=$3
    mkdir -p "/state/$config_name"
    {
      printf '%s\n' \
        'mixed-port: 7890' \
        'allow-lan: true' \
        'bind-address: "*"' \
        'mode: rule' \
        'log-level: warning' \
        'ipv6: false' \
        'proxies:' \
        '  - name: openvpn-main' \
        '    type: openvpn' \
        "    server: $server_name" \
        '    port: 1194' \
        '    proto: udp' \
        '    dev: tun' \
        '    cipher: AES-256-CBC' \
        '    data-ciphers:' \
        '      - AES-256-CBC' \
        '    auth: SHA1' \
        '    username: testuser' \
        '    password: testpass' \
        '    ca: |'
      sed 's/^/      /' /state/ca.crt
      if [ "$disable_auth_token" = true ]; then
        printf '%s\n' '    disable-auth-token: true'
      fi
      printf '%s\n' \
        '    ping: 2' \
        '    ping-restart: 20' \
        '    mtu: 1200' \
        '    udp: true' \
        'rules:' \
        '  - MATCH,openvpn-main'
    } >"/state/$config_name/config.yaml"
  }

  write_client_config static openvpn-static "${STATIC_DISABLE_AUTH_TOKEN:-true}"
  write_client_config token openvpn-token false
  write_client_config fault openvpn-fault true
  exec tail -f /dev/null
  ;;

server)
  openvpn --version | sed -n '1p'
  if [ "${AUTH_MODE:-static}" = once ]; then
    rmdir /tmp/openvpn-configured-password-used 2>/dev/null || true
  fi
  if [ "${AUTH_MODE:-static}" = active ]; then
    rmdir "$active_marker" 2>/dev/null || true
    printf '0\n' >"${CONNECTION_COUNT_FILE:?missing connection count file}"
    printf '0\n' >"${FAULT_COUNT_FILE:?missing fault count file}"
  fi
  iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j MASQUERADE
  set -- openvpn \
    --port 1194 \
    --proto udp \
    --dev tun \
    --ca /state/ca.crt \
    --cert /state/server.crt \
    --key /state/server.key \
    --dh none \
    --topology subnet \
    --server 10.8.0.0 255.255.255.0 \
    --verify-client-cert none \
    --username-as-common-name \
    --auth-user-pass-verify /usr/local/bin/openvpn-test via-file \
    --client-connect /usr/local/bin/openvpn-active-connect \
    --client-disconnect /usr/local/bin/openvpn-active-disconnect \
    --setenv ACTIVE_RELEASE_DELAY "${ACTIVE_RELEASE_DELAY:-0}" \
    --setenv AUTH_MODE "${AUTH_MODE:-static}" \
    --setenv CONNECTION_COUNT_FILE "${CONNECTION_COUNT_FILE:-}" \
    --script-security 2 \
    --cipher AES-256-CBC \
    --data-ciphers AES-256-CBC \
    --auth SHA1 \
    --disable-dco \
    --reneg-sec "${RENEG_SEC:-10}" \
    --hand-window "${HAND_WINDOW:-5}" \
    --keepalive 2 20 \
    --persist-key \
    --persist-tun \
    --explicit-exit-notify 1 \
    --verb 4
  if [ -n "${AUTH_GEN_TOKEN:-}" ]; then
    set -- "$@" --auth-gen-token "$AUTH_GEN_TOKEN"
  fi
  if [ -n "${FAULT_INTERVAL:-}" ]; then
    (
      sleep "${FAULT_START_DELAY:-5}"
      while :; do
        iptables -I INPUT 1 -p udp --dport 1194 -j REJECT --reject-with icmp-port-unreachable
        fault_count=$(cat "${FAULT_COUNT_FILE:?missing fault count file}")
        printf '%d\n' "$((fault_count + 1))" >"$FAULT_COUNT_FILE"
        sleep "${FAULT_DURATION:-0.2}"
        iptables -D INPUT -p udp --dport 1194 -j REJECT --reject-with icmp-port-unreachable
        sleep "$FAULT_INTERVAL"
      done
    ) &
  fi
  exec "$@"
  ;;

probe)
  probe_one_target() {
    startup_attempts=0
    until curl --fail --silent --show-error --max-time 2 \
      --proxy "http://$proxy_host:7890" http://172.31.0.10/ >/dev/null; do
      startup_attempts=$((startup_attempts + 1))
      if [ "$startup_attempts" -ge "${PROBE_STARTUP_ATTEMPTS:-30}" ]; then
        printf '%s failed to establish the initial OpenVPN path\n' "$proxy_host" >&2
        return 1
      fi
      sleep 1
    done

    failures=0
    attempts=0
    while [ "$attempts" -lt "${PROBE_ATTEMPTS:-1400}" ]; do
      attempts=$((attempts + 1))
      if ! curl --fail --silent --show-error --max-time "$probe_timeout" \
        --proxy "http://$proxy_host:7890" http://172.31.0.10/ >/dev/null; then
        failures=$((failures + 1))
        printf '%s probe failed: attempt=%d failures=%d\n' "$proxy_host" "$attempts" "$failures" >&2
      fi
      sleep "${PROBE_DELAY:-0.05}"
    done
    printf '%s probe complete: attempts=%d failures=%d\n' "$proxy_host" "$attempts" "$failures"
    test "$failures" -eq 0
  }

  probe_target() {
    proxy_host=$1
    probe_timeout=$2
    probe_one_target
  }

  probe_target mihomo-static "${PROBE_TIMEOUT:-0.25}" &
  static_pid=$!
  probe_target mihomo-token "${PROBE_TIMEOUT:-0.25}" &
  token_pid=$!
  probe_target mihomo-fault "${PROBE_FAULT_TIMEOUT:-3}" &
  fault_pid=$!
  status=0
  if ! wait "$static_pid"; then
    status=1
  fi
  if ! wait "$token_pid"; then
    status=1
  fi
  if ! wait "$fault_pid"; then
    status=1
  fi
  connection_count=$(cat /state/fault/connect-count)
  fault_count=$(cat /state/fault/fault-count)
  printf 'mihomo-fault session summary: connections=%d injected-faults=%d\n' "$connection_count" "$fault_count"
  if [ "$connection_count" -ne 1 ] || [ "$fault_count" -lt 10 ]; then
    status=1
  fi
  exit "$status"
  ;;

*)
  credentials_file=${1:?missing OpenVPN credentials file}
  username=$(sed -n '1p' "$credentials_file")
  password=$(sed -n '2p' "$credentials_file")
  [ "$username" = testuser ] && [ "$password" = testpass ] || exit 1
  case "${AUTH_MODE:-static}" in
  static)
    ;;
  once)
    if ! mkdir /tmp/openvpn-configured-password-used 2>/dev/null; then
      printf 'rejected reused configured password for one-time authentication\n' >&2
      exit 1
    fi
    ;;
  active)
    if [ -d "$active_marker" ]; then
      printf 'rejected duplicate login while configured user is already active\n' >&2
      exit 1
    fi
    ;;
  *)
    printf 'unknown authentication mode: %s\n' "$AUTH_MODE" >&2
    exit 1
    ;;
  esac
  ;;
esac
