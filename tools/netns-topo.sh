#!/usr/bin/env bash
# R8 lab topology on Linux network namespaces (udp-binding, M1).
#
#   r8-a (LOC 8:1::10, underlay 10.8.1.10) ── r8-rtr ── r8-b (LOC 8:2::20, underlay 10.8.2.20)
#
# The underlay is ordinary IPv4; R8 rides UDP/52808 across a stock router.
# That is the point of udp-binding: R8 crosses subnets before any R8 router
# exists. The eth-binding native forwarder is milestone M4.
set -euo pipefail

R8REF="$(cd "$(dirname "$0")/.." && pwd)/reference/r8ref.py"

cmd_setup() {
    sudo ip netns add r8-a
    sudo ip netns add r8-rtr
    sudo ip netns add r8-b

    sudo ip link add veth-a  type veth peer name veth-ar
    sudo ip link add veth-b  type veth peer name veth-br
    sudo ip link set veth-a  netns r8-a
    sudo ip link set veth-ar netns r8-rtr
    sudo ip link set veth-b  netns r8-b
    sudo ip link set veth-br netns r8-rtr

    sudo ip netns exec r8-a   ip addr add 10.8.1.10/24 dev veth-a
    sudo ip netns exec r8-rtr ip addr add 10.8.1.1/24  dev veth-ar
    sudo ip netns exec r8-rtr ip addr add 10.8.2.1/24  dev veth-br
    sudo ip netns exec r8-b   ip addr add 10.8.2.20/24 dev veth-b

    for ns in r8-a r8-rtr r8-b; do
        sudo ip netns exec "$ns" ip link set lo up
    done
    sudo ip netns exec r8-a   ip link set veth-a  up
    sudo ip netns exec r8-rtr ip link set veth-ar up
    sudo ip netns exec r8-rtr ip link set veth-br up
    sudo ip netns exec r8-b   ip link set veth-b  up

    sudo ip netns exec r8-a ip route add default via 10.8.1.1
    sudo ip netns exec r8-b ip route add default via 10.8.2.1
    sudo ip netns exec r8-rtr sysctl -qw net.ipv4.ip_forward=1

    echo "[topo] up: r8-a(8:1::10/10.8.1.10) r8-rtr r8-b(8:2::20/10.8.2.20)"
}

cmd_demo() {
    echo "[demo] listener on r8-b (LOC 8:2::20)"
    sudo ip netns exec r8-b python3 "$R8REF" listen --address 8:2::20 --bind 10.8.2.20 --allow-isolated-underlay &
    LPID=$!
    sleep 1
    echo "[demo] ping from r8-a (LOC 8:1::10) across the router"
    sudo ip netns exec r8-a python3 "$R8REF" ping \
        --address 8:1::10 --bind 10.8.1.10 --peer 8:2::20=10.8.2.20:52808 --allow-isolated-underlay --count 4 8:2::20
    echo "[demo] dgram from r8-a"
    sudo ip netns exec r8-a python3 "$R8REF" send \
        --address 8:1::10 --bind 10.8.1.10 --peer 8:2::20=10.8.2.20:52808 --allow-isolated-underlay 8:2::20 "hello over r8"
    sleep 1
    sudo kill "$LPID" 2>/dev/null || true
}

cmd_teardown() {
    for ns in r8-a r8-rtr r8-b; do
        sudo ip netns del "$ns" 2>/dev/null || true
    done
    echo "[topo] down"
}

case "${1:-}" in
    setup)    cmd_setup ;;
    demo)     cmd_demo ;;
    teardown) cmd_teardown ;;
    *) echo "usage: $0 {setup|demo|teardown}" >&2; exit 2 ;;
esac
