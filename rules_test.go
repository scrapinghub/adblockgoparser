package adblockgoparser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCommentRule(t *testing.T) {
	ruleText := "! Title: EasyList"
	rule, err := ParseRule(ruleText)
	assert.EqualError(t, err, "Commented rules are skipped")
	assert.Nil(t, rule)

	ruleText = "[Adblock Plus 2.0]"
	rule, err = ParseRule(ruleText)
	assert.EqualError(t, err, "Commented rules are skipped")
	assert.Nil(t, rule)
}

func TestHTMLRule(t *testing.T) {
	ruleText := "###AdSense1"
	rule, err := ParseRule(ruleText)
	assert.EqualError(t, err, "HTML rules are skipped")
	assert.Nil(t, rule)

	ruleText = "statejournal.com#@##WNAd41"
	rule, err = ParseRule(ruleText)
	assert.EqualError(t, err, "HTML rules are skipped")
	assert.Nil(t, rule)
}

func TestExceptionRule(t *testing.T) {
	ruleText := "@@||akamaized.net^$domain=kora-online.tv"
	expected := "||akamaized.net^"
	rule, err := ParseRule(ruleText)
	assert.NoError(t, err)
	assert.True(t, rule.isException)
	assert.Equal(t, rule.ruleText, expected)
}

func TestRuleBlockingAddressPart(t *testing.T) {
	ruleText := "/banner/*/img^"
	rule, err := ParseRule(ruleText)
	assert.NoError(t, err)

	// TODO: Change url to Request
	assert.True(t, rule.Match("http://example.com/banner/foo/img"))
	assert.True(t, rule.Match("http://example.com/banner/foo/bar/img?param"))
	assert.True(t, rule.Match("http://example.com/banner//img/foo"))
	assert.True(t, rule.Match("http://example.com/banner/foo/img:8000"))
	assert.False(t, rule.Match("http://example.com/banner/img"))
	assert.False(t, rule.Match("http://example.com/banner/foo/imgraph"))
	assert.False(t, rule.Match("http://example.com/banner/foo/img.gif"))
}

func TestRuleBlockingDomainName(t *testing.T) {
	ruleText := "||ads.example.com^"
	rule, err := ParseRule(ruleText)
	assert.NoError(t, err)

	// TODO: Change url to Request
	assert.True(t, rule.Match("http://ads.example.com/foo.gif"))
	assert.True(t, rule.Match("http://server1.ads.example.com/foo.gif"))
	assert.True(t, rule.Match("https://ads.example.com:8000/"))
	assert.False(t, rule.Match("http://ads.example.com.ua/foo.gif"))
	assert.False(t, rule.Match("http://example.com/redirect/http://ads.example.com/"))
}

func TestRuleBlockingExactAddress(t *testing.T) {
	ruleText := "|http://example.com/|"
	rule, err := ParseRule(ruleText)
	assert.NoError(t, err)

	// TODO: Change url to Request
	assert.True(t, rule.Match("http://example.com/"))
	assert.False(t, rule.Match("http://example.com/foo.gif"))
	assert.False(t, rule.Match("http://example.info/redirect/http://example.com/"))
}

func TestNewRuleSetFromStr(t *testing.T) {
	rules := []string{"/banner/*/img^", "||ads.example.com^", "|http://example.com/|"}
	ruleSet, err := NewRuleSetFromStr(rules)

	assert.NoError(t, err)

	// TODO: Change url to Request
	// First rule
	assert.False(t, ruleSet.Allow("http://example.com/banner/foo/img"))
	assert.False(t, ruleSet.Allow("http://example.com/banner/foo/bar/img?param"))
	assert.False(t, ruleSet.Allow("http://example.com/banner//img/foo"))
	assert.False(t, ruleSet.Allow("http://example.com/banner/foo/img:8000"))
	assert.True(t, ruleSet.Allow("http://example.com/banner/img"))
	assert.True(t, ruleSet.Allow("http://example.com/banner/foo/imgraph"))
	assert.True(t, ruleSet.Allow("http://example.com/banner/foo/img.gif"))

	// Second rule
	assert.False(t, ruleSet.Allow("http://ads.example.com/foo.gif"))
	assert.False(t, ruleSet.Allow("http://server1.ads.example.com/foo.gif"))
	assert.False(t, ruleSet.Allow("https://ads.example.com:8000/"))
	assert.True(t, ruleSet.Allow("http://ads.example.com.ua/foo.gif"))
	assert.True(t, ruleSet.Allow("http://example.com/redirect/http://ads.example.com/"))

	// Third rule
	assert.False(t, ruleSet.Allow("http://example.com/"))
	assert.True(t, ruleSet.Allow("http://example.com/foo.gif"))
	assert.True(t, ruleSet.Allow("http://example.info/redirect/http://example.com/"))

}
