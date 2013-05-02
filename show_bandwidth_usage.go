package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/miekg/pcap"
)

type ByteSize float64

const (
	_            = iota // ignore first value by assigning to blank identifier
	KiB ByteSize = 1 << (10 * iota)
	MiB
	GiB
	TiB
	PiB
	EiB
	ZiB
	YiB
)

func (b ByteSize) String() string {
	switch {
	case b >= YiB:
		return fmt.Sprintf("%.2f YiB", b/YiB)
	case b >= ZiB:
		return fmt.Sprintf("%.2f ZiB", b/ZiB)
	case b >= EiB:
		return fmt.Sprintf("%.2f EiB", b/EiB)
	case b >= PiB:
		return fmt.Sprintf("%.2f PiB", b/PiB)
	case b >= TiB:
		return fmt.Sprintf("%.2f TiB", b/TiB)
	case b >= GiB:
		return fmt.Sprintf("%.2f GiB", b/GiB)
	case b >= MiB:
		return fmt.Sprintf("%.2f MiB", b/MiB)
	case b >= KiB:
		return fmt.Sprintf("%.2f KiB", b/KiB)
	}
	return fmt.Sprintf("%.2f B", b)
}

type SortedTrafficEntries []Traffic

func (st SortedTrafficEntries) Len() int { return len(st) }
func (st SortedTrafficEntries) Less(i, j int) bool {
	return (st[i].In + st[i].Out) > (st[j].In + st[j].Out)
}
func (st SortedTrafficEntries) Swap(i, j int) { st[i], st[j] = st[j], st[i] }

type Traffic struct {
	In   uint32
	Out  uint32
	Addr string
}

var transferredBytes struct {
	sync.Mutex
	traffic map[string]*Traffic
}

const TYPE_IP = 0x0800

func sniff(device string, subnet string) {
	h, err := pcap.OpenLive(device, 65535, true, 0)
	if h == nil {
		panic(err)
	}
	err = h.SetFilter(fmt.Sprintf("net %s", subnet))
	if err != nil {
		panic(err)
	}
	_, ipnet, _ := net.ParseCIDR(subnet)
	for pkt := h.Next(); pkt != nil; pkt = h.Next() {
		pkt.Decode()
		if pkt.Type == TYPE_IP {
			if iphdr, ok := pkt.Headers[0].(*pcap.Iphdr); ok {
				srcIP := net.ParseIP(iphdr.SrcAddr())
				strSrcIP := iphdr.SrcAddr()
				dstIP := net.ParseIP(iphdr.DestAddr())
				strDstIP := iphdr.DestAddr()
				if ipnet.Contains(srcIP) {
					transferredBytes.Lock()
					if _, ok := transferredBytes.traffic[strSrcIP]; ok {
						t := transferredBytes.traffic[strSrcIP]
						t.Out += pkt.Len
					} else {
						transferredBytes.traffic[strSrcIP] = &Traffic{0, pkt.Len, strSrcIP}
					}
					transferredBytes.Unlock()
				}
				if ipnet.Contains(dstIP) {
					transferredBytes.Lock()
					if _, ok := transferredBytes.traffic[strDstIP]; ok {
						t := transferredBytes.traffic[strDstIP]
						t.In += pkt.Len
					} else {
						transferredBytes.traffic[strDstIP] = &Traffic{pkt.Len, 0, strDstIP}
					}
					transferredBytes.Unlock()
				}
			}
		}
	}
}

func main() {
	transferredBytes.traffic = make(map[string]*Traffic)

	device := flag.String("i", "", "interface to capture on")
	interval := flag.Int("n", 1, "update interval")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s -i <interface> [-n <interval>] <subnet>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *device == "" {
		fmt.Fprintln(os.Stderr, "Please provide the interface to capture on.")
		os.Exit(1)
	}
	if len(flag.Args()) < 1 {
		fmt.Fprintln(os.Stderr, "Please provide the IP subnet of the hosts to monitor.")
		os.Exit(1)
	}
	subnet := flag.Arg(0)

	go sniff(*device, subnet)
	var printedLines int

	for {
		time.Sleep(time.Duration(*interval*1000) * time.Millisecond)
		for i := 0; i < printedLines; i++ {
			fmt.Printf("\033[A\033[2K")
		}
		printedLines = 0

		transferredBytes.Lock()
		st := make(SortedTrafficEntries, 0, len(transferredBytes.traffic))
		for _, v := range transferredBytes.traffic {
			st = append(st, *v)
		}
		// reset traffic for all IPs
		transferredBytes.traffic = make(map[string]*Traffic)
		transferredBytes.Unlock()

		sort.Sort(st)
		for _, v := range st {
			if printedLines >= 5 {
				break
			}
			fmt.Printf("%s\t\tD: %s/s\t\tU: %s/s\n", v.Addr, ByteSize(v.In/uint32(*interval)).String(), ByteSize(v.Out/uint32(*interval)).String())
			printedLines++
		}
	}
}
