#!/bin/bash

# Set up 2 veth peers and give them IPs
ip link del dev veth1 2>/dev/null || :
ip link del dev veth2 2>/dev/null || :
ip link add veth1 type veth peer veth2
ip addr add 192.168.4.1/24 dev veth1
ip addr add 192.168.4.2/24 dev veth2
ip addr add 2001:db8::1:100/64 dev veth1
ip addr add 2001:db8::1:101/64 dev veth2
ip link set dev veth1 up
ip link set dev veth2 up

# Give some time for the interfaces to come up
sleep 1

export LD_LIBRARY_PATH="../build"

# Run all tests from directory
tests=$(find * -type f -name 'test_*')

for f in $tests
do
    if test -x ./"$f"; then
        if ./"$f" > ./"$f".out 2> ./"$f".err; then
            echo "PASS: $f"
        else
            echo "FAIL: $f"
        fi
    fi
done

# When done, delete the peers
ip link del dev veth1 2>/dev/null || :
ip link del dev veth2 2>/dev/null || :
