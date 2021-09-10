package urlfilter

import (
	"io"
	"os"
	"testing"

	"github.com/AdguardTeam/golibs/log"
)

func TestMain(m *testing.M) {
	// TODO(a.garipov): Refactor code and tests to not use the global
	// mutable logger.
	log.SetOutput(io.Discard)

	os.Exit(m.Run())
}
