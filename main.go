package main

import (
	"fmt"
	"log"
	"os"

	"github.com/Ullaakut/nmap"
)

func main() {
	// Equivalent to `/usr/local/bin/nmap -p 80,443,843 google.com facebook.com youtube.com`
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(os.Args...),
		nmap.WithServiceInfo(),       // -sV flag
		nmap.WithDefaultScript(),     // -sC flag
		nmap.WithSkipHostDiscovery(), // -Pn flag
		// nmap.WithOSDetection(),       // -O flag
	)

	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	result, warnings, err := scanner.Run()

	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	if warnings != nil {
		log.Printf("Warnings: \n %v", warnings)
	}

	// Use the results to print an example output
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		fmt.Printf("Host %q:\n", host.Addresses[0])

		for _, port := range host.Ports {
			fmt.Printf("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
		}
	}

	fmt.Printf("Nmap done: %d hosts up scanned in %3f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)

}
