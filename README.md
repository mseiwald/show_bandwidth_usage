# Simple bandwidth monitor written in Go

Shows how much bandwidth (Download + Upload) is consumed by which host in a
specified IP subnet on a specified network interface. Supposed to be run on a
Linux router.

# Installation

On Debian-based systems:
    apt-get install golang build-essential git libpcap-dev
    go get show_bandwidth_usage.go
    go build show_bandwidth_usage.go

# Usage

Example:

    $ ping -i .2 -s 4096 8.8.8.8 > /dev/null &  # generate some traffic...
    [1] 5839
    # ./show_bandwidth_usage -i eth0 192.168.0.0/16
    192.168.100.91      D: 66.00 B/s        U: 20.79 KiB/s
    192.168.100.100     D: 258.00 B/s       U: 66.00 B/s
