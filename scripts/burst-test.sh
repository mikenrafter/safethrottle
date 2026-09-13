#!/usr/bin/env bash
# Burst-test safethrottle against Substack.
#
# Usage:
#   burst-test.sh          # parallel (default)
#   burst-test.sh parallel 20
#   burst-test.sh seq 20    # one-at-a-time
#
# Prints completion order (done=1 is first to finish) vs launch order.
# Launch progress goes to stderr so stdout stays easy to pipe/sort.

set -euo pipefail

mode=${1:-parallel}
count=${2:-20}
url_base=${URL:-https://www.substack.com/}
lock=$(mktemp)
counter=$(mktemp)
echo 0 >"$counter"
trap 'rm -f "$lock" "$counter"' EXIT

run_one() {
  local launch=$1
  echo "launch=$launch" >&2
  local tls total
  read -r tls total < <(
    curl -sS -o /dev/null \
      --http1.1 \
      --no-alpn \
      -H 'Connection: close' \
      --max-time "${MAX_TIME:-120}" \
      -w "%{time_appconnect} %{time_total}" \
      "${url_base}?n=${launch}"
  )
  {
    flock 9
    local done=$(( $(cat "$counter") + 1 ))
    echo "$done" >"$counter"
    printf 'done=%d launch=%d tls=%s total=%s\n' "$done" "$launch" "$tls" "$total"
  } 9>"$lock"
}

if [[ "$mode" == "seq" || "$mode" == "sequential" ]]; then
  for i in $(seq 1 "$count"); do
    run_one "$i"
  done
else
  for i in $(seq 1 "$count"); do
    run_one "$i" &
  done
  wait
fi
