package fingerprint

import (
	"fmt"
	"testing"
)

func TestPhpEnv(t *testing.T) {
	filtered, _ := phpEnv()
	fmt.Println(filtered)
}
