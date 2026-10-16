#!/bin/sh
set -eu
getent group weroxy >/dev/null || groupadd --system weroxy
getent passwd weroxy >/dev/null || useradd --system --gid weroxy --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin weroxy
install -d -o root -g weroxy -m 0750 /etc/weroxycli
install -d -o root -g root -m 0700 /var/cache/weroxy-client
# Provision the invoking user's profile without giving root a home-path write.
# Package managers run as root; sudo/pkexec preserve the caller's numeric UID.
profile_uid=${SUDO_UID:-${PKEXEC_UID:-$(id -u)}}
case "$profile_uid" in ''|*[!0-9]*) echo 'Invalid installing user UID' >&2; exit 1;; esac
profile_user=$(getent passwd "$profile_uid" | cut -d: -f1)
[ -n "$profile_user" ] || exit 1
runuser -u "$profile_user" -- /usr/bin/weroxy-client profile-init
# Old copied installs override vendor units. Save the exact owned files first.
old_unit=/etc/systemd/system/weroxycli.service
migrating=false
was_enabled=false
if [ -d /run/systemd/system ] && systemctl is-enabled --quiet weroxycli.service; then was_enabled=true; fi
if [ -f "$old_unit" ] && [ ! -L "$old_unit" ] && grep -q 'ExecStart=.*\/usr\/local\/bin\/weroxy-client.*run.*--config' "$old_unit"; then
  install -d -m 0700 /var/cache/weroxy-client/migration
  cp -p "$old_unit" /var/cache/weroxy-client/migration/weroxycli.service
  [ ! -f /usr/local/bin/weroxy-client ] || cp -p /usr/local/bin/weroxy-client /var/cache/weroxy-client/migration/weroxy-client
  rm "$old_unit"
  migrating=true
fi
if [ -d /run/systemd/system ]; then
 systemctl daemon-reload
 # Strengthen on newer systemd, while keeping the base unit valid on 219.
 ver=$(systemctl --version | sed -n '1s/systemd \([0-9]*\).*/\1/p')
 if [ "${ver:-0}" -ge 232 ]; then
  install -d -m 0755 /etc/systemd/system/weroxycli.service.d
  printf '[Service]\nProtectSystem=strict\n' > /etc/systemd/system/weroxycli.service.d/package-hardening.conf
 fi
 systemctl daemon-reload
 if [ "$migrating" = true ] && [ "$was_enabled" = true ]; then systemctl reenable weroxycli.service; fi
 if [ "$migrating" = true ] && ! /usr/bin/weroxy-client version >/dev/null 2>&1; then
  cp -p /var/cache/weroxy-client/migration/weroxycli.service "$old_unit"
  systemctl daemon-reload
  exit 1
 fi
 if systemctl is-active --quiet weroxycli.service; then
  healthy=false
  if systemctl restart weroxycli.service; then
   if [ "$migrating" = true ]; then
    n=0
    while [ "$n" -lt 30 ]; do
     if /usr/bin/weroxy-client status --config /etc/weroxycli/client.conf --json 2>/dev/null | grep -q '"connected":true'; then healthy=true; break; fi
     n=$((n+1)); sleep 1
    done
   else healthy=true; fi
  fi
  if [ "$healthy" = true ]; then
   if [ "$migrating" = true ]; then rm -f /usr/local/bin/weroxy-client; fi
  else
   if [ "$migrating" = true ]; then cp -p /var/cache/weroxy-client/migration/weroxycli.service "$old_unit"; systemctl daemon-reload; systemctl restart weroxycli.service; fi
   exit 1
  fi
 fi
 # Inactive migrations retain the private rollback copy, but must not leave
 # an obsolete executable ahead of /usr/bin in PATH. The package version and
 # vendor unit have been checked; the original inactive state is preserved.
 if [ "$migrating" = true ]; then rm -f /usr/local/bin/weroxy-client; fi
fi
