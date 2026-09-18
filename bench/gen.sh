#!/bin/sh
# Writes the inputs of the himorime suite in bench/. Deterministic: the same
# arguments always write the same data, so a base and a head revision read
# the same input. Both revisions run the working tree's copy (${head_root}).
#
#   sh gen.sh db N DIR   an onionscan.db in DIR holding two scans of one
#                        onion service with N findings each (see gendb/)
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)

case "$1" in
db)
	cd "$root"
	go run ./bench/gendb -findings "$2" -dir "$3"
	;;
*)
	echo "gen.sh: unknown kind $1" >&2
	exit 2
	;;
esac
