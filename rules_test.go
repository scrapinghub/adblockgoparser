package adblockgoparser

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCommentRule(t *testing.T) {
	ruleText := "! Title: EasyList"
	rule, err := ParseRule(ruleText)
	assert.Equal(t, errors.Is(err, ErrSkipComment), true)
	assert.Nil(t, rule)

	ruleText = "[Adblock Plus 2.0]"
	rule, err = ParseRule(ruleText)
	assert.Equal(t, errors.Is(err, ErrSkipComment), true)
	assert.Nil(t, rule)
}

func TestHTMLRule(t *testing.T) {
	ruleText := "###AdSense1"
	rule, err := ParseRule(ruleText)
	assert.Equal(t, errors.Is(err, ErrSkipHTML), true)
	assert.Nil(t, rule)

	ruleText = "statejournal.com#@##WNAd41"
	rule, err = ParseRule(ruleText)
	assert.Equal(t, errors.Is(err, ErrSkipHTML), true)
	assert.Nil(t, rule)
}

func TestExceptionRule(t *testing.T) {
	ruleText := "@@||akamaized.net^$domain=kora-online.tv"
	expected := "||akamaized.net^"
	rule, err := ParseRule(ruleText)
	assert.Nil(t, err)
	assert.Equal(t, rule.isException, true)
	assert.Equal(t, rule.ruleText, expected)
}

func TestRuleBlockingAddressPart(t *testing.T) {
	ruleText := "/banner/*/img^"
	rule, err := ParseRule(ruleText)
	assert.Nil(t, err)

	// TODO: Change url to Request
	assert.Equal(t, rule.Allow("http://example.com/banner/foo/img"), false)
	assert.Equal(t, rule.Allow("http://example.com/banner/foo/bar/img?param"), false)
	assert.Equal(t, rule.Allow("http://example.com/banner//img/foo"), false)
	assert.Equal(t, rule.Allow("http://example.com/banner/img"), true)
	assert.Equal(t, rule.Allow("http://example.com/banner/foo/imgraph"), true)
	assert.Equal(t, rule.Allow("http://example.com/banner/foo/img.gif"), true)
}

func TestRuleBlockingDomainName(t *testing.T) {
	ruleText := "||ads.example.com^"
	rule, err := ParseRule(ruleText)
	assert.Nil(t, err)

	// TODO: Change url to Request
	assert.Equal(t, rule.Allow("http://ads.example.com/foo.gif"), false)
	assert.Equal(t, rule.Allow("http://server1.ads.example.com/foo.gif"), false)
	assert.Equal(t, rule.Allow("https://ads.example.com:8000/"), false)
	assert.Equal(t, rule.Allow("http://ads.example.com.ua/foo.gif"), true)
	assert.Equal(t, rule.Allow("http://example.com/redirect/http://ads.example.com/"), true)
}

func TestRuleBlockingExactAddress(t *testing.T) {
	ruleText := "|http://example.com/|"
	rule, err := ParseRule(ruleText)
	assert.Nil(t, err)

	// TODO: Change url to Request
	assert.Equal(t, rule.Allow("http://example.com/"), false)
	assert.Equal(t, rule.Allow("http://example.com/foo.gif"), true)
	assert.Equal(t, rule.Allow("http://example.info/redirect/http://example.com/"), true)
}
