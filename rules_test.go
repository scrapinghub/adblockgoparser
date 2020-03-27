package adblockgoparser

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParsingCommentRule(t *testing.T) {
	ruleText := "[Adblock Plus 2.0]"
	_, err := ParseRule(ruleText)
	assert.EqualError(t, err, "Commented rules are skipped")
}

func TestParsingHTMLRule(t *testing.T) {
	ruleText := "###AdSense1"
	_, err := ParseRule(ruleText)
	assert.EqualError(t, err, "HTML rules are skipped")
}

func TestParsingBadOptionRule(t *testing.T) {
	ruleText := "||domain.net^$badoption"
	_, err := ParseRule(ruleText)
	assert.EqualError(t, err, "Unsupported option rules are skipped")
}

func TestCommentRule(t *testing.T) {
	ruleText := "[Adblock Plus 2.0]"
	rules := []string{ruleText}
	_, err := NewRuleSetFromList(rules)
	assert.EqualError(t, err, "Commented rules are skipped: [Adblock Plus 2.0]")

	ruleText = "! Title: EasyList"
	rules = []string{ruleText}
	_, err = NewRuleSetFromList(rules)
	assert.EqualError(t, err, "Commented rules are skipped: ! Title: EasyList")
}

func TestHTMLRule(t *testing.T) {
	ruleText := "###AdSense1"
	rules := []string{ruleText}
	_, err := NewRuleSetFromList(rules)
	assert.EqualError(t, err, "HTML rules are skipped: ###AdSense1")

	ruleText = "statejournal.com#@##WNAd41"
	rules = []string{ruleText}
	_, err = NewRuleSetFromList(rules)
	assert.EqualError(t, err, "HTML rules are skipped: statejournal.com#@##WNAd41")

	ruleText = "mobile.twitter.com#?#.tweet:-abp-has(.promo)"
	rules = []string{ruleText}
	_, err = NewRuleSetFromList(rules)
	assert.EqualError(t, err, "HTML rules are skipped: mobile.twitter.com#?#.tweet:-abp-has(.promo)")
}

func TestBadOptionRule(t *testing.T) {
	ruleText := "||domain.net^$badoption"
	rules := []string{ruleText}
	_, err := NewRuleSetFromList(rules)
	assert.EqualError(t, err, "Unsupported option rules are skipped: ||domain.net^$badoption")
}

func TestExceptionRule(t *testing.T) {
	ruleText := "@@||domain.net^$domain=otherdomain.net"
	rules := []string{ruleText}
	ruleSet, err := NewRuleSetFromList(rules)
	assert.NoError(t, err)
	child, exists := ruleSet.whitelistTrie.hasChild("net")
	assert.True(t, exists)
	assert.NotNil(t, child)
	child, exists = child.hasChild("otherdomain")
	assert.True(t, exists)
	assert.NotNil(t, child)
}

func reqFromURL(rawURL string) Request {
	reqUrl, _ := url.ParseRequestURI(rawURL)
	req := Request{
		URL:     reqUrl,
		Origin:  "",
		Referer: "",
		IsXHR:   false,
	}
	return req
}

func TestNewRuleSetFromListWithWhitelist(t *testing.T) {
	rules := []string{"/banner/*/img^", "||ads.example.com^", "|http://example.com/|"}

	ruleSet, err := NewRuleSetFromList(rules)
	assert.NoError(t, err)

	// First rule
	assert.False(t, ruleSet.Allow(reqFromURL("http://example.com/banner/foo/img")))
	assert.False(t, ruleSet.Allow(reqFromURL("http://example.com/banner/foo/bar/img?param")))
	assert.False(t, ruleSet.Allow(reqFromURL("http://example.com/banner//img/foo")))
	assert.False(t, ruleSet.Allow(reqFromURL("http://example.com/banner/foo/img:8000")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://example.com/banner/img")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://example.com/banner/foo/imgraph")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://example.com/banner/foo/img.gif")))

	// Second rule
	assert.False(t, ruleSet.Allow(reqFromURL("http://ads.example.com/foo.gif")))
	assert.False(t, ruleSet.Allow(reqFromURL("http://server1.ads.example.com/foo.gif")))
	assert.False(t, ruleSet.Allow(reqFromURL("https://ads.example.com:8000/")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://ads.example.com.ua/foo.gif")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://example.com/redirect/http://ads.example.com/")))

	// Third rule
	assert.False(t, ruleSet.Allow(reqFromURL("http://example.com/")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://example.com/foo.gif")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://example.info/redirect/http://example.com/")))

	// Now add some exceptions
	rules = []string{
		"/banner/*/img^",
		"||ads.example.com^",
		"|http://example.com/|",
		"@@/banner/*/img^",
		"@@||ads.example.com^",
		"@@|http://example.com/|",
	}
	ruleSet, err = NewRuleSetFromList(rules)
	assert.NoError(t, err)

	// First rule
	assert.True(t, ruleSet.Allow(reqFromURL("http://example.com/banner/foo/img")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://example.com/banner/foo/bar/img?param")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://example.com/banner//img/foo")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://example.com/banner/foo/img:8000")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://example.com/banner/img")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://example.com/banner/foo/imgraph")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://example.com/banner/foo/img.gif")))

	// Second rule
	assert.True(t, ruleSet.Allow(reqFromURL("http://ads.example.com/foo.gif")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://server1.ads.example.com/foo.gif")))
	assert.True(t, ruleSet.Allow(reqFromURL("https://ads.example.com:8000/")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://ads.example.com.ua/foo.gif")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://example.com/redirect/http://ads.example.com/")))

	// Third rule
	assert.True(t, ruleSet.Allow(reqFromURL("http://example.com/")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://example.com/foo.gif")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://example.info/redirect/http://example.com/")))
}

func TestRuleWithScriptOption(t *testing.T) {
	// Only block script
	rules := []string{"||ads.example.com^$script"}
	ruleSet, err := NewRuleSetFromList(rules)
	assert.NoError(t, err)
	assert.True(t, ruleSet.Allow(reqFromURL("http://ads.example.com/")))
	assert.False(t, ruleSet.Allow(reqFromURL("http://ads.example.com/file.js")))

	// Only allow script
	rules = []string{"||ads.example.com^$~script"}
	ruleSet, err = NewRuleSetFromList(rules)
	assert.NoError(t, err)
	assert.False(t, ruleSet.Allow(reqFromURL("http://ads.example.com/")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://ads.example.com/file.js")))
}

func TestRuleWithScriptOptionOnWhitelist(t *testing.T) {
	// Block everything on ads.example.com domain, except if it is script
	rules := []string{"||ads.example.com^", "@@||ads.example.com^$script"}
	ruleSet, err := NewRuleSetFromList(rules)
	assert.NoError(t, err)
	assert.False(t, ruleSet.Allow(reqFromURL("http://ads.example.com/")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://ads.example.com/file.js")))

	// Block everything on ads.example.com domain, except if it is not script
	rules = []string{"||ads.example.com^", "@@||ads.example.com^$~script"}
	ruleSet, err = NewRuleSetFromList(rules)
	assert.NoError(t, err)
	assert.True(t, ruleSet.Allow(reqFromURL("http://ads.example.com/")))
	assert.False(t, ruleSet.Allow(reqFromURL("http://ads.example.com/file.js")))
}

func TestRuleWithDomainOption(t *testing.T) {
	rules := []string{"/banner/*/img$domain=example.com|~bar.example.com"}
	ruleSet, err := NewRuleSetFromList(rules)
	assert.NoError(t, err)
	// Block for `example.com` domain and its subdomain
	assert.False(t, ruleSet.Allow(reqFromURL("http://example.com/banner/foo/img")))
	assert.False(t, ruleSet.Allow(reqFromURL("http://anysubdomain.example.com/banner/foo/img")))
	// But not for `bar` subdomain and its subdomain or other domain
	assert.True(t, ruleSet.Allow(reqFromURL("http://bar.example.com/banner/foo/img")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://foo.bar.example.com/banner/foo/img")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://example.net/banner/foo/img")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://anysubdomain.example.net/banner/foo/img")))
}

func TestRuleWithDomainOptionAndMoreOptions(t *testing.T) {
	rules := []string{"||example.com^$script,domain=example.com|~bar.example.com", "||nonrelated.com^$script"}
	ruleSet, err := NewRuleSetFromList(rules)
	assert.NoError(t, err)
	// Block for `example.com` domain and its subdomain, since it is script
	assert.False(t, ruleSet.Allow(reqFromURL("http://example.com/file.js")))
	assert.False(t, ruleSet.Allow(reqFromURL("http://anysubdomain.example.com/file.js")))
	// Do not block if it is not script
	assert.True(t, ruleSet.Allow(reqFromURL("http://example.com/banner/foo/img")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://anysubdomain.example.com/banner/foo/img")))
	// Do not block for `bar` subdomain and its subdomain or other domain, even for script
	assert.True(t, ruleSet.Allow(reqFromURL("http://bar.example.com/banner/foo/img")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://foo.bar.example.com/banner/foo/img")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://example.net/banner/foo/img")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://anysubdomain.example.net/banner/foo/img")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://bar.example.com/banner/foo/file.js")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://foo.bar.example.com/banner/foo/file.js")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://example.net/banner/foo/file.js")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://anysubdomain.example.net/banner/foo/file.js")))
}

func TestRuleSetWithStyleSheetOption(t *testing.T) {
	rules := []string{"banner/foo/*$stylesheet"}
	ruleSet, err := NewRuleSetFromList(rules)
	assert.NoError(t, err)
	assert.False(t, ruleSet.Allow(reqFromURL("http://ads.example.com/banner/foo/file.css")))
}

func TestRuleSetWithStyleSheetOptionAndDomainRule(t *testing.T) {
	rules := []string{"||ads.example.com^$stylesheet"}
	ruleSet, err := NewRuleSetFromList(rules)
	assert.NoError(t, err)
	assert.False(t, ruleSet.Allow(reqFromURL("http://ads.example.com/banner/foo/file.css")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://ads.example.com/banner/foo/file.js")))
}

func TestRuleSetWithNegateStyleSheetOptionAndDomainRule(t *testing.T) {
	rules := []string{"||ads.example.com^$~stylesheet"}
	ruleSet, err := NewRuleSetFromList(rules)
	assert.NoError(t, err)
	assert.True(t, ruleSet.Allow(reqFromURL("http://ads.example.com/banner/foo/file.css")))
	assert.False(t, ruleSet.Allow(reqFromURL("http://ads.example.com/banner/foo/file.js")))
}

func TestRuleSetWithNegateStyleSheetOption(t *testing.T) {
	rules := []string{"banner/foo/*$~stylesheet"}
	ruleSet, err := NewRuleSetFromList(rules)
	assert.NoError(t, err)
	assert.True(t, ruleSet.Allow(reqFromURL("http://ads.example.com/banner/foo/file.css")))
	assert.False(t, ruleSet.Allow(reqFromURL("http://ads.example.com/banner/foo/file.js")))
}

func TestRuleSetN1(t *testing.T) {
	rules := []string{"banner/foo/*$stylesheet,domain=example.com"}
	ruleSet, err := NewRuleSetFromList(rules)
	assert.NoError(t, err)
	assert.False(t, ruleSet.Allow(reqFromURL("http://ads.example.com/banner/foo/file.css")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://ads.example.com/banner/foo/file.js")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://ads.other.com/banner/foo/file.css")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://ads.other.com/banner/foo/file.js")))
}
func TestRuleSetN2(t *testing.T) {
	rules := []string{"banner/foo/*$~stylesheet,domain=example.com"}
	ruleSet, err := NewRuleSetFromList(rules)
	assert.NoError(t, err)
	assert.True(t, ruleSet.Allow(reqFromURL("http://ads.example.com/banner/foo/file.css")))
	assert.False(t, ruleSet.Allow(reqFromURL("http://ads.example.com/banner/foo/file.js")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://ads.other.com/banner/foo/file.css")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://ads.other.com/banner/foo/file.js")))
}
func TestRuleSetN3(t *testing.T) {
	rules := []string{"banner/foo/*$stylesheet,domain=~example.com"}
	ruleSet, err := NewRuleSetFromList(rules)
	assert.NoError(t, err)
	assert.True(t, ruleSet.Allow(reqFromURL("http://ads.example.com/banner/foo/file.css")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://ads.example.com/banner/foo/file.js")))
	assert.False(t, ruleSet.Allow(reqFromURL("http://ads.other.com/banner/foo/file.css")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://ads.other.com/banner/foo/file.js")))
}

func TestRuleSetN4(t *testing.T) {
	rules := []string{"banner/foo/*$~stylesheet,domain=~example.com"}
	ruleSet, err := NewRuleSetFromList(rules)
	assert.NoError(t, err)
	assert.True(t, ruleSet.Allow(reqFromURL("http://ads.example.com/banner/foo/file.css")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://ads.example.com/banner/foo/file.js")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://ads.other.com/banner/foo/file.css")))
	assert.False(t, ruleSet.Allow(reqFromURL("http://ads.other.com/banner/foo/file.js")))
}
func TestRuleSetN5(t *testing.T) {
	rules := []string{"banner/foo/*$~stylesheet,domain=example.com", "*$stylesheet"}
	ruleSet, err := NewRuleSetFromList(rules)
	assert.NoError(t, err)
	assert.False(t, ruleSet.Allow(reqFromURL("http://ads.example.com/banner/foo/file.css")))
	assert.False(t, ruleSet.Allow(reqFromURL("http://ads.example.com/banner/foo/file.js")))
	assert.False(t, ruleSet.Allow(reqFromURL("http://ads.other.com/banner/foo/file.css")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://ads.other.com/banner/foo/file.js")))
}
func TestRuleSetN6(t *testing.T) {
	rules := []string{"banner/foo/*$stylesheet,domain=example.com", "*$~stylesheet"}
	ruleSet, err := NewRuleSetFromList(rules)
	assert.NoError(t, err)
	assert.False(t, ruleSet.Allow(reqFromURL("http://ads.example.com/banner/foo/file.css")))
	assert.False(t, ruleSet.Allow(reqFromURL("http://ads.example.com/banner/foo/file.js")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://ads.other.com/banner/foo/file.css")))
	assert.False(t, ruleSet.Allow(reqFromURL("http://ads.other.com/banner/foo/file.js")))
}

func TestExtractOptionsFromRequest(t *testing.T) {
	reqUrl, _ := url.ParseRequestURI("http://example.com/banner/foo/file.js")
	req := Request{
		URL:     reqUrl,
		Origin:  "https://www.other.com",
		Referer: "https://www.other.com/anything",
		IsXHR:   false,
	}
	options := extractOptionsFromRequest(&req)
	assert.True(t, options["script"])
	assert.True(t, options["third-party"])
	assert.False(t, options["image"])
	assert.False(t, options["stylesheet"])
	assert.False(t, options["font"])
	assert.False(t, options["xmlhttprequest"])
}
