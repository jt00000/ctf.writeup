#!/bin/bash
if [ $# -eq 0 ]; then
    echo "Usage: ./socat.sh [ BINARY ]"
    exit 1
fi
socat TCP-LISTEN:31337,reuseaddr,fork EXEC:$1
