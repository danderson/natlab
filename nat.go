package main

import (
	"context"
	"fmt"
	"net"
	"time"

	nfqueue "github.com/florianl/go-nfqueue"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

func nat(c *cli.Context) error {
	log.Info("Starting")

	config := nfqueue.Config{
		NfQueue:      42,
		MaxPacketLen: 65535,
		MaxQueueLen:  255,
		Copymode:     nfqueue.NfQnlCopyPacket,
		ReadTimeout:  10 * time.Millisecond,
		WriteTimeout: 15 * time.Millisecond,
	}

	queue, err := nfqueue.Open(&config)
	if err != nil {
		log.Fatalf("Connecting to NFQUEUE: %s", err)
	}
	defer queue.Close()

	wanIPs, err := getWANIPs(*wanIf)
	if err != nil {
		log.Fatalf("Getting WAN IPs: %s", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	translator := NewAddressAndPortDependentNAT(wanIPs)

	process := func(a nfqueue.Attribute) int {
		pkt := NewPacket(*a.Payload)
		if pkt == nil {
			// We don't know how to handle this kind of packet
			queue.SetVerdict(*a.PacketID, nfqueue.NfDrop)
			return 0
		}
		intf, err := net.InterfaceByIndex(int(*a.InDev))
		if err != nil {
			panic(err)
		}

		verdict := TranslatorVerdictDrop
		switch intf.Name {
		case *lanIf:
			verdict = translator.TranslateOutUDP(*a.Payload)
		case *wanIf:
			verdict = translator.TranslateInUDP(*a.Payload)
		}

		switch verdict {
		case TranslatorVerdictAccept:
			queue.SetVerdict(*a.PacketID, nfqueue.NfAccept)
		case TranslatorVerdictDrop:
			queue.SetVerdict(*a.PacketID, nfqueue.NfDrop)
		case TranslatorVerdictMangle:
			queue.SetVerdictModPacket(*a.PacketID, nfqueue.NfAccept, *a.Payload)
		}

		return 0
	}
	err = queue.Register(ctx, process)
	if err != nil {
		log.Fatalf("Couldn't register packet processor: %s", err)
	}

	log.Info("Created tuns")
	<-ctx.Done()
	log.Info("Exiting")

	return nil
}

func getWANIPs(ifName string) ([]net.IP, error) {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("Getting %s interface info: %s", ifName, err)
	}

	ret := []net.IP{}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("Getting %s interface addrs: %s", ifName, err)
	}
	for _, addr := range addrs {
		ipaddr := addr.(*net.IPAddr)
		if ipaddr == nil || ipaddr.IP.To4() == nil || !ipaddr.IP.IsGlobalUnicast() {
			continue
		}
		ret = append(ret, ipaddr.IP)
	}

	return ret, nil
}
