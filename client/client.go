package main

import (
	"flag"
	"log"
	"net"
	"strconv"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/dermesser/clusterrpc/client"
	rpclog "github.com/dermesser/clusterrpc/log"
	"github.com/dermesser/clusterrpc/securitymanager"
)

func extractQueryHost(pkg []byte) (string, error) {
	p := dnsmessage.Parser{}
	_, err := p.Start(pkg)
	if err != nil {
		return "", err
	}
	hosts := ""
	for {
		q, err := p.Question()
		if err != nil && err != dnsmessage.ErrSectionDone {
			return "", err
		}
		if err == dnsmessage.ErrSectionDone {
			break
		}
		hosts += q.Name.String() + " "
	}
	return hosts, nil
}

type dnsclient struct {
	rpccl    *client.Client
	listener *net.UDPConn
}

func (dc *dnsclient) run() {
	pkg := make([]byte, 1500)

	for {
		sz, from, err := dc.listener.ReadFrom(pkg)
		if err != nil {
			log.Print(err)
			continue
		}
		log.Println("Received", sz, "bytes from", from)

		hosts, err := extractQueryHost(pkg[0:sz])
		if err != nil {
			log.Print(err)
			continue
		}
		log.Print(hosts)

		resp, err := dc.rpccl.Request(pkg[0:sz], "DNSOverRPC", "Resolve", nil)
		if err != nil {
			log.Print(err)
			continue
		}

		sz, err = dc.listener.WriteTo(resp, from)
		if err != nil {
			log.Print(err)
			continue
		}
		if sz < len(resp) {
			log.Print("truncated send:", sz, "<", len(resp))
		}
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	rpclog.SetLoglevel(rpclog.LOGLEVEL_INFO)

	addr := flag.String("addr", "127.0.0.1:5353", "Listen address for DNS stub")
	serverAddr := flag.String("server", "127.0.0.1:53", "Upstream resolver address")
	pubkeyfile := flag.String("pubkeyfile", "", "Public key file for RPC encryption")
	privkeyfile := flag.String("privkeyfile", "", "Private key file for RPC encryption")
	flag.Parse()

	sm := securitymanager.NewClientSecurityManager()
	sm.LoadKeys(*pubkeyfile, *privkeyfile)

	if *pubkeyfile == "" || *privkeyfile == "" {
		sm = nil
	}

	host, port, err := net.SplitHostPort(*serverAddr)
	if err != nil {
		log.Fatal(err)
	}
	iport, err := strconv.Atoi(port)
	if err != nil {
		log.Fatal(err)
	}

	peer := client.Peer(host, uint(iport))
	ch, err := client.NewChannelAndConnect(peer, sm)
	if err != nil {
		log.Fatal(err)
	}
	cl := client.New("Main", ch)

	ua, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	uc, err := net.ListenUDP("udp", ua)
	if err != nil {
		log.Fatal(err)
	}
	dc := dnsclient{rpccl: &cl, listener: uc}
	dc.run()
}
