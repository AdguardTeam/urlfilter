package rules_test

import (
	"testing"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/urlfilter/rules"
	"github.com/stretchr/testify/assert"
)

// testFilterListID is a test filter list ID.
const testFilterListID = 1

func TestNewRule(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		in         string
		name       string
		wantErrMsg string
		wantNil    bool
	}{{
		in:         "",
		name:       "empty",
		wantErrMsg: "",
		wantNil:    true,
	}, {
		in:         " ",
		name:       "space",
		wantErrMsg: "",
		wantNil:    true,
	}, {
		in:         "  ",
		name:       "double_space",
		wantErrMsg: "",
		wantNil:    true,
	}, {
		in:         "! comment",
		name:       "comment",
		wantErrMsg: "",
		wantNil:    true,
	}, {
		in:         "#",
		name:       "comment_hash",
		wantErrMsg: "",
		wantNil:    true,
	}, {
		in:         "# comment",
		name:       "comment_hash_space",
		wantErrMsg: "",
		wantNil:    true,
	}, {
		in:         "##banner",
		name:       "element_hiding",
		wantErrMsg: "",
		wantNil:    false,
	}, {
		in:         "209.237.226.90 example.test",
		name:       "host",
		wantErrMsg: "",
		wantNil:    false,
	}, {
		in:         "||example.test^",
		name:       "network",
		wantErrMsg: "",
		wantNil:    false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r, err := rules.NewRule(tc.in, testFilterListID)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)

			if tc.wantNil {
				assert.Nil(t, r)
			} else {
				assert.NotNil(t, r)
				assert.Equal(t, testFilterListID, r.GetFilterListID())
				assert.Equal(t, tc.in, r.Text())
			}
		})
	}
}

func FuzzNewRule(f *testing.F) {
	for _, seed := range []string{
		"",
		" ",
		"\n",
		"!",
		"#",
		"# comment",
		"##banner",
		"::1 localhost",
		"209.237.226.90 example.test",
		"fe80::1 # comment",
		"||example.org^",
		"/regex/",
		"@@||example.org^$third-party",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, in string) {
		assert.NotPanics(t, func() {
			_, _ = rules.NewRule(in, testFilterListID)
		})
	})
}
