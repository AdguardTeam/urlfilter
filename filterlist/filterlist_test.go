package filterlist_test

import (
	"strings"

	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
)

// Common list IDs for tests.
const (
	testListID      rules.ListID = 1
	testListIDOther rules.ListID = 2
)

// Common domains for tests.
const testDomain = "test.example"

// Common rules for tests.
const (
	testRuleDomain   = "||" + testDomain
	testRuleCosmetic = "##banner"
	testComment      = "! comment"
)

// Common text rules for tests.
const (
	testRuleTextDomain   = testRuleDomain + "\n"
	testRuleTextCosmetic = testRuleCosmetic + "\n"
	testCommentText      = testComment + "\n"

	testRuleText      = testRuleTextDomain + testCommentText + testRuleTextCosmetic
	testRuleTextOther = "||example.com\n! test\n##advert\n"
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
	testStrgID1Rule1 = filterlist.NewStorageID(testListID, 0)
	testStrgID1Rule2 = filterlist.NewStorageID(testListID, 25)
	testStrgID2Rule1 = filterlist.NewStorageID(testListIDOther, 0)
	testStrgID2Rule2 = filterlist.NewStorageID(testListIDOther, 21)
)
