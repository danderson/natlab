package main

import (
	"encoding/binary"
	"flag"
	"net"

	"github.com/sirupsen/logrus"
)

var (
	udpPort1 = flag.Int("udp1", 443, "UDP listener #1 address")
	udpPort2 = flag.Int("udp2", 4001, "UDP listener #2 address")
)

func main() {
	ips, err := publicIPs()
	if err != nil {
		logrus.Fatalf("Couldn't list public IPs: %s", err)
	}
	if len(ips) < 2 {
		logrus.Warn("Not enough public IPs available to provide a useful testing server")
	}

	ports := []int{*udpPort1, *udpPort2}

	server := &server{}

	for _, ip := range ips {
		for _, port := range ports {
			addr := &net.UDPAddr{IP: ip, Port: port}
			conn, err := net.ListenUDP("udp4", addr)
			if err != nil {
				logrus.Fatalf("Failed to listen on %s: %s", addr, err)
			}
			server.conns = append(server.conns, conn)
			logrus.Infof("Listening on %s", addr)
		}
	}

	for _, conn := range server.conns {
		go server.handle(conn)
	}

	logrus.Info("Startup complete")
	select {}
}

type server struct {
	conns []*net.UDPConn
}

func (s *server) handle(conn *net.UDPConn) error {
	var buf [1500]byte
	for {
		n, addr, err := conn.ReadFromUDP(buf[:])
		if err != nil {
			logrus.Errorf("Reading on %s: %s", conn.LocalAddr(), err)
		}
		if n != 180 {
			logrus.Infof("Received malformed %d byte packet from %s", n, addr)
			continue
		}

		key := buf[0]
		respConn := conn
		if key > 0 {
			respConn = s.conns[int(key-1)%len(s.conns)]
		}

		copy(buf[:16], addr.IP.To16())
		binary.BigEndian.PutUint16(buf[16:18], uint16(addr.Port))
		if _, err = respConn.WriteToUDP(buf[:18], addr); err != nil {
			logrus.Errorf("Failed to send response to %s: %s", addr, err)
			continue
		}

		logrus.Infof("Provided NAT mapping to %s via %s", addr, respConn.LocalAddr())
	}
}

func publicIPs() ([]net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var ret []net.IP

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, genAddr := range addrs {
			addr, ok := genAddr.(*net.IPNet)
			if !ok || addr.IP.To4() == nil || !addr.IP.IsGlobalUnicast() || isrfc1918(addr.IP) {
				continue
			}
			ret = append(ret, addr.IP.To4())
		}
	}

	return ret, nil
}

func isrfc1918(ip net.IP) bool {
	ip = ip.To4()
	return ip[0] == 10 ||
		(ip[0] == 172 && ip[1]&0xf0 == 16) ||
		(ip[0] == 192 && ip[1] == 168)
}
