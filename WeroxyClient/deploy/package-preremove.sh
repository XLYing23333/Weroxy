#!/bin/sh
set -eu
# This hook is called only for actual removal, not a package upgrade.
if [ -d /run/systemd/system ]; then
 systemctl stop weroxycli.service || :
 systemctl disable weroxycli.service || :
fi
# Remove only the exact drop-in created by this package.
dropin=/etc/systemd/system/weroxycli.service.d/package-hardening.conf
if [ -f "$dropin" ] && [ ! -L "$dropin" ] && [ "$(cat "$dropin")" = "$(printf '[Service]\nProtectSystem=strict\n')" ]; then
 rm -f "$dropin"
 rmdir /etc/systemd/system/weroxycli.service.d 2>/dev/null || :
fi
