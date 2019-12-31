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
		Name:  "NATlab",
		Usage: "Testbed for NAT traversal software",
		Commands: []*cli.Command{
			{
				Name:   "nat",
				Usage:  "Intercept and mangle packets, acting as a NAT box",
				Hidden: true,
				Action: natbox,
			},
			{
				Name:   "generate",
				Usage:  "Generate a docker-compose configuration for the specified network topoloy",
				Action: func(c *cli.Context) error { return nil },
			},
		},
	}

	app.Run(os.Args)
}
