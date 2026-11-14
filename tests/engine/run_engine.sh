#!/bin/sh

HERE=$(cd "$(dirname "$0")" && pwd)
BIN=${MONNETT:-$HERE/../../engine/build/monnett}
PCAP=${PCAP:-$HERE/../pcaps/monnett-examples.pcap}
TMP=$(mktemp -d /tmp/monnett-run-XXXXXX)
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0
skip=0

ok() { pass=$((pass + 1)); echo "PASS  $1"; }
bad() { fail=$((fail + 1)); echo "FAIL  $1"; [ -n "$2" ] && echo "$2" | sed 's/^/      /'; }

expect_exit() {
    want=$1
    name=$2
    shift 2
    out=$("$@" 2>&1)
    got=$?
    if [ "$got" -eq "$want" ]; then ok "$name (exit $got)"; else bad "$name (exit $got, want $want)" "$out"; fi
}

captured() {
    "$@" 2>/dev/null | sed -n 's/^\[end\] captured=\([0-9]*\).*/\1/p'
}

expect_count() {
    want=$1
    name=$2
    shift 2
    got=$(captured "$@")
    if [ "$got" = "$want" ]; then ok "$name ($got packets)"; else bad "$name (got '$got', want $want)"; fi
}

printf '[engine]\nsource = "lo"\n' > "$TMP/ok.toml"
chmod 644 "$TMP/ok.toml"
printf '[engine]\nsource = "lo"\n' > "$TMP/open.toml"
chmod 666 "$TMP/open.toml"
printf '[engine]\nsorce = "lo"\n' > "$TMP/bad.toml"
chmod 644 "$TMP/bad.toml"
printf '[engine]\npool_slots = 10\n' > "$TMP/range.toml"
chmod 644 "$TMP/range.toml"
C="--config $TMP/ok.toml"

echo "== arguments"
expect_exit 0 "-h" "$BIN" -h
expect_exit 1 "unknown short option" "$BIN" -x
expect_exit 1 "unknown long option" "$BIN" --foo
expect_exit 1 "-i without value" "$BIN" -i
expect_exit 1 "extra argument" "$BIN" $C extra

echo "== config"
expect_exit 2 "missing --config file" "$BIN" --config "$TMP/nope.toml"
expect_exit 2 "unknown key" "$BIN" --config "$TMP/bad.toml"
expect_exit 2 "value out of range" "$BIN" --config "$TMP/range.toml"
expect_exit 3 "config writable by others" "$BIN" --config "$TMP/open.toml"
expect_exit 2 "missing .pcap" "$BIN" $C -i "$TMP/gone.pcap"

can_capture=1
"$BIN" $C -i "$PCAP" >/dev/null 2>&1
rc=$?
if [ "$rc" -eq 8 ]; then
    can_capture=0
    echo "(no CAP_SYS_NICE: run with sudo or setcap for the capture tests)"
fi

echo "== file capture"
if [ "$can_capture" -eq 1 ]; then
    expect_exit 0 "read .pcap" "$BIN" $C -i "$PCAP"
    expect_count 12 "all packets" "$BIN" $C -i "$PCAP"
    expect_count 6 "filter udp" "$BIN" $C -i "$PCAP" -f "udp"
    expect_count 12 "filter in any order" "$BIN" $C -f "" -i "$PCAP"
    expect_exit 5 "bad filter" "$BIN" $C -i "$PCAP" -f "tcp and"
    expect_exit 4 "no such interface" "$BIN" $C -i nosuch0
else
    skip=$((skip + 6))
fi

echo "== live capture on lo"
live=0
if [ "$can_capture" -eq 1 ]; then
    "$BIN" $C -i lo -f "udp port 1" >/dev/null 2>&1 &
    probe=$!
    sleep 0.5
    kill -INT $probe 2>/dev/null
    wait $probe
    [ $? -eq 0 ] && live=1
fi
if [ "$live" -eq 0 ]; then
    echo "(no CAP_NET_RAW: live tests skipped)"
    skip=$((skip + 6))
else
    for sig in INT TERM; do
        "$BIN" $C -i lo -f "udp port 47999" > "$TMP/live.txt" 2>&1 &
        pid=$!
        sleep 0.5
        python3 -c "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); [s.sendto(b'x' * 100, ('127.0.0.1', 47999)) for i in range(500)]"
        sleep 1.5
        if [ "$sig" = INT ]; then
            tasks=$(ls /proc/$pid/task)
            dln=0
            caps=0
            for t in $tasks; do
                grep -q '^policy.*: *6$' /proc/$pid/task/$t/sched 2>/dev/null && dln=$((dln + 1))
                grep -q '^CapEff:.*0000000000000000' /proc/$pid/task/$t/status && caps=$((caps + 1))
            done
            [ "$dln" -eq 1 ] && ok "one thread runs SCHED_DEADLINE" || bad "SCHED_DEADLINE threads: $dln"
            n=$(echo $tasks | wc -w)
            [ "$caps" -eq "$n" ] && ok "no capabilities left in any of $n threads" || bad "threads without caps: $caps of $n"
        fi
        kill -$sig $pid
        wait $pid
        rc=$?
        got=$(sed -n 's/^\[end\] captured=\([0-9]*\).*/\1/p' "$TMP/live.txt")
        [ "$rc" -eq 0 ] && ok "SIG$sig stops cleanly (exit 0)" || bad "SIG$sig exit $rc" "$(cat "$TMP/live.txt")"
        [ "$got" = 500 ] && ok "SIG$sig run captured 500 packets" || bad "SIG$sig run captured '$got', want 500"
    done
fi

echo
echo "$pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ]
