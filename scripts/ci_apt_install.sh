#!/usr/bin/env bash
# Installs Ubuntu packages on a GitHub-hosted runner without waiting on a slow
# mirror. Usage: scripts/ci_apt_install.sh PACKAGE...
#
# The Azure mirror the runners prefer can keep transferring at a very low speed
# without timing out: installing tor took between 18 and 205 seconds in the
# Coverage job on 2026-11-19. So this script prefers the official Ubuntu HTTPS
# archive (keeping the runner's other mirrors as fallbacks), lets apt retry a
# failed or stalled connection, and bounds the two network phases, the index
# update and the download, with a deadline. A phase that passes its deadline is
# started again, up to three attempts; apt resumes the partial downloads. The
# packages are unpacked only after every file is on disk, so the deadline never
# interrupts dpkg. The script is the one gozen uses (scripts/ci_apt_install.sh).
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: $0 PACKAGE..." >&2
  exit 2
fi

if [ -f /etc/apt/apt-mirrors.txt ]; then
  sudo sed -i \
    -e '\|^http://azure\.archive\.ubuntu\.com/ubuntu/|s/priority:1/priority:2/' \
    -e '\|^https://archive\.ubuntu\.com/ubuntu/|s/priority:2/priority:1/' \
    /etc/apt/apt-mirrors.txt
fi

apt_options=(-o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o DPkg::Lock::Timeout=60)
install=(install -y --no-install-recommends)

for attempt in 1 2 3; do
  if sudo timeout --kill-after=10 60 apt-get "${apt_options[@]}" update &&
    sudo timeout --kill-after=10 90 apt-get "${apt_options[@]}" "${install[@]}" --download-only "$@"; then
    sudo apt-get "${apt_options[@]}" "${install[@]}" "$@"
    exit 0
  fi
  echo "apt attempt ${attempt} of 3 failed or passed its deadline" >&2
  sleep $((attempt * 10))
done
exit 1
