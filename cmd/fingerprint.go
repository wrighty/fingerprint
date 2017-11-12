package main

import (
	"crypto/sha1"
	"flag"
	"fmt"
	"log"

	"github.com/wrighty/fingerprint"
)

func main() {
	var verbose = flag.Bool("verbose", false, "Print details for each fingerprint")
	flag.Parse()

	fps, err := fingerprint.GenerateFingerprints()
	if err != nil {
		log.Fatal(err)
	}

	hash := sha1.New()
	for _, fp := range fps {
		hash.Write([]byte(fp.Details))
	}
	fmt.Printf("%x", hash.Sum(nil))
	if *verbose {
		for _, fp := range fps {
			fmt.Println(fp.Source)
			fmt.Println(fp.Details)
			fmt.Println(fp.SHA1)
		}
	}

}
