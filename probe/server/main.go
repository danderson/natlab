package main

import (
	"encoding/binary"
	"flag"
	"net"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

var (
	ports = flag.String("ports", "80,443,500,1194,1701,1723,3478,4500,5060,5061,51820,60000", "UDP listener ports")
)

func main() {
	ips, err := publicIPs()
	if err != nil {
		logrus.Fatalf("Couldn't list public IPs: %s", err)
	}
	if len(ips) < 2 {
		logrus.Warn("Not enough public IPs available to provide a useful testing server")
	}

	ports, err := parsePorts()
	if err != nil {
		logrus.Fatalf("Failed to parse ports: %s", err)
	}

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

func parsePorts() ([]int, error) {
	ret := []int{}
	for _, port := range strings.Split(*ports, ",") {
		i, err := strconv.Atoi(port)
		if err != nil {
			return nil, err
		}
		ret = append(ret, i)
	}
	return ret, nil
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
			logrus.Infof("Received malformed %d byte packet from %s on %s", n, addr, conn.LocalAddr())
			continue
		}

		varyAddr, varyPort := buf[0] == 1, buf[1] == 1
		var respConn *net.UDPConn
		for _, c := range s.conns {
			myaddr := conn.LocalAddr().(*net.UDPAddr)
			uaddr := c.LocalAddr().(*net.UDPAddr)
			if uaddr.IP.Equal(myaddr.IP) == varyAddr {
				continue
			}
			if (uaddr.Port == myaddr.Port) == varyPort {
				continue
			}
			respConn = c
			break
		}

		copy(buf[:16], addr.IP.To16())
		binary.BigEndian.PutUint16(buf[16:18], uint16(addr.Port))
		if _, err = respConn.WriteToUDP(buf[:18], addr); err != nil {
			logrus.Errorf("Failed to send response to %s: %s", addr, err)
			continue
		}

		logrus.Infof("Provided NAT mapping to %s via %s (varyAddr=%t, varyPort=%t)", addr, respConn.LocalAddr(), varyAddr, varyPort)
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
