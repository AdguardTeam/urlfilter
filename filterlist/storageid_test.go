package filterlist_test

import (
	"testing"

	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStorageID_UnmarshalBinary(t *testing.T) {
	orig := testStrgID1Rule2

	data, err := orig.AppendBinary(nil)
	require.NoError(t, err)

	var decoded filterlist.StorageID
	err = decoded.UnmarshalBinary(data)
	require.NoError(t, err)

	assert.Equal(t, orig, decoded)
}

func BenchmarkStorageID_UnmarshalBinary(b *testing.B) {
	orig := testStrgID1Rule2

	data, err := orig.AppendBinary(nil)
	require.NoError(b, err)

	var decoded filterlist.StorageID
	b.ReportAllocs()
	for b.Loop() {
		err = decoded.UnmarshalBinary(data)
	}

	require.NoError(b, err)
	require.Equal(b, orig, decoded)

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/urlfilter/filterlist
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkStorageID_UnmarshalBinary-16    	80872926	        14.66 ns/op	       0 B/op	       0 allocs/op
}
