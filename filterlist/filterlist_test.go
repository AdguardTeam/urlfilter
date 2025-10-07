package filterlist_test

import (
	"strings"

	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/internal/uftest"
)

// Common rules for tests.
const (
	testRuleCosmetic = "##banner"
	testComment      = "! comment"
)

// Common text rules for tests.
const (
	testRuleTextDomain   = uftest.RuleHost + "\n"
	testRuleTextCosmetic = testRuleCosmetic + "\n"
	testCommentText      = testComment + "\n"

	testRuleText      = testRuleTextDomain + testCommentText + testRuleTextCosmetic
	testRuleTextOther = uftest.RuleHostOther + "\n! test\n##advert\n"
)

const (
	// testResourcesDir is the path to test resources.
	testResourcesDir = "../testdata"

	// hostsPath is the path to hosts file for testing.
	hostsPath = testResourcesDir + "/hosts"

	// hostsRulesCount is the number of rules in the hosts file available by
	// hostsPath.
	//
	// NOTE:  Keep in sync with hostsPath file contents.
	hostsRulesCount = 55997
)

// cosmeticRuleIndex is the index of the cosmetic rule in [testRuleText].
var cosmeticRuleIndex = int64(strings.Index(testRuleText, testRuleCosmetic))

// Common StorageIDs for tests.
//
// NOTE:  Keep in sync with [testRuleText] and [testRuleTextOther].
var (
	testStrgID1Rule1 = filterlist.NewStorageID(uftest.ListID1, 0)
	testStrgID1Rule2 = filterlist.NewStorageID(uftest.ListID1, 26)
	testStrgID2Rule1 = filterlist.NewStorageID(uftest.ListID2, 0)
	testStrgID2Rule2 = filterlist.NewStorageID(uftest.ListID2, 24)
)
