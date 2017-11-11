package fingerprint

import (
	"bufio"
	"crypto/sha1"
	"fmt"
	"log"
	"os/exec"
	"sort"
	"strings"
)

//Package designates a named package installed at a particular version
type Package struct {
	Name    string
	Version string
}

//FingerPrint represents a single finger print type that is both a hash and the raw details
type FingerPrint struct {
	Source  string
	SHA1    string
	Details string
}

//borrowing heavily from Clair and https://github.com/coreos/clair/blob/master/ext/featurefmt/rpm/rpm.go
func rpmInstalledPackages() ([]Package, error) {
	var packages []Package
	//	dir := "/var/log/rpm/"
	//	out, err := exec.Command("rpm", "--dbpath", dir, "-qa", "--qf", "%{NAME} %{EPOCH}:%{VERSION}-%{RELEASE}\n").CombinedOutput()
	out, err := exec.Command("rpm", "-qa", "--qf", "%{NAME} %{EPOCH}:%{VERSION}-%{RELEASE}\n").CombinedOutput()
	if err != nil {
		log.Print(err)
		log.Fatal("could not query RPM")
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.Split(scanner.Text(), " ")
		if len(line) != 2 {
			// We may see warnings on some RPM versions:
			// "warning: Generating 12 missing index(es), please wait..."
			continue
		}

		// Ignore gpg-pubkey packages which are fake packages used to store GPG keys - they are not versionned properly.
		if line[0] == "gpg-pubkey" {
			continue
		}

		// Parse version
		version := strings.Replace(line[1], "(none):", "", -1)
		pkg := Package{
			Name:    line[0],
			Version: version,
		}
		packages = append(packages, pkg)
	}

	return packages, nil
}

func fmtRPMPackages(pkgs []Package) string {
	var s []string
	for _, pkg := range pkgs {
		s = append(s, pkg.Name+"#"+pkg.Version)
	}
	sort.Strings(s)

	return strings.Join(s, "\n")
}

func phpEnv() (string, error) {
	filteredOut := ""
	out, err := exec.Command("php", "-i").CombinedOutput()
	if err != nil {
		return "", err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		//skip host specific details
		line := strings.Split(scanner.Text(), "System => ")
		if len(line) == 2 {
			continue
		}

		//after this it's all host / shell specifics
		if line[0] == "Environment" {
			break
		}

		filteredOut = filteredOut + "\n" + line[0]

	}
	return filteredOut, nil
}

//GenerateFingerprints extracts fingerprint data from the host and returns hashs and details of each source
func GenerateFingerprints() (map[string]FingerPrint, error) {
	fps := make(map[string]FingerPrint)

	rpm, err := rpmInstalledPackages()
	if err != nil {
		return nil, err
	}

	fmtRPM := fmtRPMPackages(rpm)
	fps["rpm"] = FingerPrint{
		Source:  "rpm",
		SHA1:    sha(fmtRPM),
		Details: fmtRPM,
	}

	php, err := phpEnv()
	if err != nil {
		return nil, err
	}
	fps["php"] = FingerPrint{
		Source:  "php",
		SHA1:    sha(php),
		Details: php,
	}
	return fps, nil
}

func sha(s string) string {
	return fmt.Sprintf("%x", sha1.Sum([]byte(s)))
}
