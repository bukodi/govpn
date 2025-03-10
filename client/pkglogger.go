package main

import (
	"log/slog"
)

var pkgLogger = slog.With("pkg", "client")
