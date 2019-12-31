package main

import (
	"flag"
	"os"

	"github.com/urfave/cli/v2"
)

var (
	lanIf = flag.String("lan-interface", "eth0", "name of the LAN interface")
	wanIf = flag.String("wan-interface", "eth1", "name of the WAN interface")
)

func main() {
	app := &cli.App{
		Name:  "natlab",
		Usage: "Testbed for NAT traversal software",
		Commands: []*cli.Command{
			{
				Name:  "nat",
				Usage: "hook into kernel datapath and operate as a NAT box",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "lan-interface",
						Aliases:  []string{"L"},
						Required: true,
						Usage:    "name of the LAN-side network interface",
					},
					&cli.StringFlag{
						Name:     "wan-interface",
						Aliases:  []string{"W"},
						Required: true,
						Usage:    "name of the WAN-side network interface",
					},
				},
				Action: nat,
			},
		},
	}
	app.Run(os.Args)
}
