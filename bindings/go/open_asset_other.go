// Copyright 2026 Encypher Corporation
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package c2pa

import (
	"errors"
	"os"
)

func openAsset(_ string) (*os.File, error) {
	return nil, errors.New("path-based verification is unsupported on this platform")
}
