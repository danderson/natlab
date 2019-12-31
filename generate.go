package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

func generate(c *cli.Context) error {
	if !c.Args().Present() {
		log.Fatalf("Generate requires a datapath spec")
	}
	spec := c.Args().First()
	log.Infof("spec: %s", spec)

	// TODO: parser for a network description language, poop out
	// corresponding docker-compose. Example network descriptions:
	//
	// client(net=lan1) client(net=lan2) nat(lan=lan1,wan=internet) nat(lan=lan2,wan=internet) stun(net=internet)
	// client(net=lan1) client(net=lan2) nat(lan=lan1,wan=cgnat1) nat(lan=lan2,wan=cgnat1) nat(lan=cgnat1,wan=internet) stun(net=internet)

	return nil
}
