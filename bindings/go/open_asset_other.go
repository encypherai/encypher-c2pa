//go:build !linux && !darwin

package c2pa

import (
	"errors"
	"os"
)

func openAsset(_ string) (*os.File, error) {
	return nil, errors.New("path-based verification is unsupported on this platform")
}
