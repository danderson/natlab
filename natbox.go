package main

import (
	"context"
	"net"
	"time"

	"github.com/florianl/go-nfqueue"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

func natbox(c *cli.Context) error {
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	iface, err := net.InterfaceByName(*wanIf)
	if err != nil {
		log.Fatalf("Getting %s interface info: %s", *wanIf, err)
	}

	var publicAddr net.IP
	addrs, err := iface.Addrs()
	if err != nil {
		log.Fatalf("Getting %s interface addrs: %s", *wanIf, err)
	}
	for _, addr := range addrs {
		ipaddr := addr.(*net.IPNet)
		if ipaddr == nil || ipaddr.IP.To4() == nil {
			continue
		}
		publicAddr = ipaddr.IP
		break
	}

	conntrack := NewAddressAndPortDependentNAT(publicAddr)

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

		verdict := VerdictDrop
		switch intf.Name {
		case *lanIf:
			verdict = conntrack.MangleOutbound(pkt)
		case *wanIf:
			verdict = conntrack.MangleInbound(pkt)
		}

		switch verdict {
		case VerdictAccept:
			queue.SetVerdict(*a.PacketID, nfqueue.NfAccept)
		case VerdictDrop:
			queue.SetVerdict(*a.PacketID, nfqueue.NfDrop)
		case VerdictMangle:
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
