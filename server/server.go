package main

import (
	"flag"
	"log"
	"net"
	"strconv"
	"time"

	rpclog "github.com/dermesser/clusterrpc/log"
	"github.com/dermesser/clusterrpc/securitymanager"
	"github.com/dermesser/clusterrpc/server"
	"golang.org/x/net/dns/dnsmessage"
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

// Internal request to the serializer.
type request struct {
	pkg  []byte
	resp chan []byte
}

// Serialize queries to simplify matching. Acts as a server via req channel.
type serializer struct {
	upstream string
	conn     *net.UDPConn
	n        int

	reqs chan request
}

// Serve requests one by one
func (s *serializer) run() {
	if s.conn == nil {
		ua, err := net.ResolveUDPAddr("udp", s.upstream)
		if err != nil {
			log.Fatal(err)
		}
		conn, err := net.DialUDP("udp", nil, ua)
		if err != nil {
			log.Fatal(err)
		}
		s.conn = conn
	}

	for req := range s.reqs {
		pkg := req.pkg
		respch := req.resp

		hosts, err := extractQueryHost(pkg)
		if err != nil {
			log.Print("Invalid DNS package:", err)
			respch <- nil
			continue
		}
		log.Println("Serializer", s.n, "querying:", hosts)

		sz, err := s.conn.Write(pkg)
		if err != nil {
			log.Print(err)
			respch <- nil
			continue
		}
		if sz != len(pkg) {
			log.Println("Warning: Wrote only", sz, "of", len(pkg), "bytes!")
		}
		dst := make([]byte, 1500)
		s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		sz, err = s.conn.Read(dst)
		if err != nil {
			log.Print(err)
			respch <- nil
			continue
		}
		respch <- dst[0:sz]
	}
}

type resolver struct {
	reqs chan request
	ch   chan []byte
}

func (r *resolver) handle(c *server.Context) {
	pkg := c.GetInput()
	if r.ch == nil {
		r.ch = make(chan []byte)
	}
	r.reqs <- request{pkg, r.ch}
	resp := <-r.ch
	if resp == nil {
		c.Fail("Lookup didn't succeed")
		return
	}
	c.Success(resp)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	rpclog.SetLoglevel(rpclog.LOGLEVEL_INFO)

	addr := flag.String("addr", "127.0.0.1:5555", "Listen address for RPC server")
	upstream := flag.String("upstream", "127.0.0.1:53", "Upstream resolver address")
	pubkeyfile := flag.String("pubkeyfile", "", "Public key file for RPC encryption")
	privkeyfile := flag.String("privkeyfile", "", "Private key file for RPC encryption")
	flag.Parse()

	sm := securitymanager.NewServerSecurityManager()
	if *pubkeyfile == "" || *privkeyfile == "" {
		sm = nil
		log.Print("null policy")
	} else {
		err := sm.LoadKeys(*pubkeyfile, *privkeyfile)
		if err != nil {
			log.Fatal(err)
		}
		log.Print("CURVE policy")
	}
	sm.ResetBlackWhiteLists()

	host, port, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatal(err)
	}
	iport, err := strconv.Atoi(port)
	if err != nil {
		log.Fatal(err)
	}
	srv, err := server.NewServer(host, uint(iport), 2, sm)
	if err != nil {
		log.Fatal(err)
	}

	const numSerializers = 10
	reqs := make(chan request)
	for i := 0; i < numSerializers; i++ {
		s := &serializer{upstream: *upstream, reqs: reqs, n: i}
		go s.run()
	}
	r := &resolver{reqs: reqs}
	srv.RegisterHandler("DNSOverRPC", "Resolve", r.handle)

	log.Println(srv.Start())
}
