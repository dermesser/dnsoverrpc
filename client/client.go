package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"strconv"

	"github.com/dermesser/clusterrpc/client"
	rpclog "github.com/dermesser/clusterrpc/log"
	"github.com/dermesser/clusterrpc/securitymanager"
	"golang.org/x/net/dns/dnsmessage"
)

const MAX_DNS_PACKET_SIZE = 65535

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
	n        int
}

func (dc *dnsclient) run() {
	pkg := make([]byte, MAX_DNS_PACKET_SIZE)
	log.Println("Resolver", dc.n, "ready")

	for {
		sz, from, err := dc.listener.ReadFrom(pkg)
		if err != nil {
			log.Print(err)
			continue
		}

		hosts, err := extractQueryHost(pkg[0:sz])
		if err != nil {
			log.Print(err)
			continue
		}
		log.Println("Resolver", dc.n, "resolving", hosts)

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
	numClients := flag.Int("threads", 20, "How many parallel requests can be served")
	serverAddr := flag.String("server", "127.0.0.1:53", "DNSOverRPC server address")
	pubkeyfile := flag.String("pubkeyfile", "", "Public key file of the server for RPC encryption")
	flag.Parse()

	sm := securitymanager.NewClientSecurityManager()

	if *pubkeyfile == "" {
		sm = nil
	} else {
		err := sm.LoadServerPubkey(*pubkeyfile)
		if err != nil {
			log.Fatal(err)
		}
	}

	host, port, err := net.SplitHostPort(*serverAddr)
	if err != nil {
		log.Fatal(err)
	}
	iport, err := strconv.Atoi(port)
	if err != nil {
		log.Fatal(err)
	}

	ua, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	uc, err := net.ListenUDP("udp", ua)
	if err != nil {
		log.Fatal(err)
	}

	for i := 0; i < *numClients; i++ {
		peer := client.Peer(host, uint(iport))
		ch, err := client.NewChannelAndConnect(peer, sm)
		if err != nil {
			log.Fatal(err)
		}
		cl := client.New(fmt.Sprintf("Resolver%d", i), ch)
		dc := dnsclient{rpccl: &cl, listener: uc, n: i}
		if i < *numClients-1 {
			go dc.run()
		} else {
			dc.run()
		}
	}
}
