package urlfilter

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/AdguardTeam/golibs/log"
)

func TestMain(m *testing.M) {
	// TODO(a.garipov): Refactor code and tests to not use the global
	// mutable logger.
	log.SetOutput(ioutil.Discard)

	os.Exit(m.Run())
}
