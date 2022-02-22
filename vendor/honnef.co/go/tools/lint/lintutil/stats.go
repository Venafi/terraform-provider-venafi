//go:build !aix && !android && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris
// +build !aix,!android,!darwin,!dragonfly,!freebsd,!linux,!netbsd,!openbsd,!solaris

package lintutil

import "os"

var infoSignals = []os.Signal{}
