package filterutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsDomainName(t *testing.T) {
	assert.True(t, IsDomainName("1.cc"))
	assert.True(t, IsDomainName("1.2.cc"))
	assert.True(t, IsDomainName("a.b.cc"))
	assert.True(t, IsDomainName("abc.abc.abc"))
	assert.True(t, IsDomainName("a-bc.ab--c.abc"))
	assert.True(t, IsDomainName("abc.xn--p1ai"))
	assert.True(t, IsDomainName("xn--p1ai.xn--p1ai"))
	assert.True(t, IsDomainName("123456789012345678901234567890123456789012345678901234567890123.cc"))
	assert.True(t, IsDomainName("cc"))
	assert.True(t, IsDomainName("xn--p1ai"))

	assert.False(t, IsDomainName("#cc"))
	assert.False(t, IsDomainName("a.cc#"))
	assert.False(t, IsDomainName("abc.xn--"))
	assert.False(t, IsDomainName("abc.xn--asd"))

	assert.False(t, IsDomainName(".a.cc"))
	assert.False(t, IsDomainName("a.cc."))

	assert.False(t, IsDomainName("-a.cc"))
	assert.False(t, IsDomainName("a-.cc"))

	assert.False(t, IsDomainName("a.1cc"))
	assert.False(t, IsDomainName("a.cc1"))
	assert.False(t, IsDomainName("a.c"))

	assert.False(t, IsDomainName("1234567890123456789012345678901234567890123456789012345678901234.cc"))
}
