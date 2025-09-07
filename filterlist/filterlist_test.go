package filterlist_test

import (
	"strings"
)

// Common list IDs for tests.
//
// TODO(a.garipov):  Introduce a type, rules.ListID.
const (
	testListID      int = 1
	testListIDOther int = 2
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
var cosmeticRuleIndex = strings.Index(testRuleText, testRuleCosmetic)

// Common StorageIDs for tests.
//
// NOTE:  Keep in sync with [testRuleText] and [testRuleTextOther].
//
// TODO(a.garipov):  Introduce a type, filterlist.StorageID.
const (
	testStrgID1Rule1 = int64(testListID<<32 | 0&0xFFFFFFFF)
	testStrgID1Rule2 = int64(testListID<<32 | 25&0xFFFFFFFF)
	testStrgID2Rule1 = int64(testListIDOther<<32 | 0&0xFFFFFFFF)
	testStrgID2Rule2 = int64(testListIDOther<<32 | 21&0xFFFFFFFF)
)
