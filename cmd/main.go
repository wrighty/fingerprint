package main

import (
	"crypto/sha1"
	"fmt"
	"log"

	"github.com/wrighty/fingerprint"
)

func main() {

	fps, err := fingerprint.GenerateFingerprints()
	if err != nil {
		log.Fatal(err)
	}

	hash := sha1.New()
	for _, fp := range fps {
		hash.Write([]byte(fp.Details))
	}
	fmt.Printf("%x", hash.Sum(nil))

}
