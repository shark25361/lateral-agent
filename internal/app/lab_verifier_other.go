//go:build !windows

package app

import "fmt"

func destinationProcessIdentity() (string, bool, error) {
	return "", false, fmt.Errorf("destination verification requires Windows")
}
