package adblockgoparser

import (
	"net/url"
	"os"
	"strconv"
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

func TestUnsupportedOptionRule(t *testing.T) {
	ruleText := "||domain.net^$badoption"
	rule, err := ParseRule(ruleText)
	assert.EqualError(t, err, "Unsupported option rules are skipped")
	assert.Nil(t, rule)
}

func TestExceptionRule(t *testing.T) {
	ruleText := "@@||domain.net^$domain=otherdomain.net"
	expected := "||domain.net^"
	rule, err := ParseRule(ruleText)
	assert.NoError(t, err)
	assert.True(t, rule.isException)
	assert.Equal(t, rule.ruleText, expected)
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

func TestNewRuleSetFromStr(t *testing.T) {
	rules := []string{"/banner/*/img^", "||ads.example.com^", "|http://domain.com/|"}
	ruleSet, err := NewRuleSetFromStr(rules)

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
	assert.False(t, ruleSet.Allow(reqFromURL("http://domain.com/")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://domain.com/foo.gif")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://domain.info/redirect/http://domain.com/")))

}

func TestNewRuleSetFromLongStr(t *testing.T) {
	rulesStr := make([]string, 67000)
	for i := range rulesStr {
		rulesStr[i] = "/page/" + strconv.Itoa(i) + "/banner/*/img^"
	}
	// Make the last rule the correct one
	rulesStr[len(rulesStr)-1] = "/banner/*/img^"

	ruleSet, err := NewRuleSetFromStr(rulesStr)

	assert.NoError(t, err)
	assert.False(t, ruleSet.Allow(reqFromURL("http://example.com/banner/foo/img")))
	assert.False(t, ruleSet.Allow(reqFromURL("http://example.com/banner/foo/bar/img?param")))
	assert.False(t, ruleSet.Allow(reqFromURL("http://example.com/banner//img/foo")))
	assert.False(t, ruleSet.Allow(reqFromURL("http://example.com/banner/foo/img:8000")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://example.com/banner/img")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://example.com/banner/foo/imgraph")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://example.com/banner/foo/img.gif")))
}

func TestNewRuleSetFromFile(t *testing.T) {
	path := "easylist.txt"
	// Create file
	f, err := os.Create(path)
	defer os.Remove(path)
	defer f.Close()
	data := []byte("[Adblock comment\n!Other comment\nanyhtmlrule.com#@##AdImage\n/banner/*/img^\n||ads.example.com^\n|http://example.com/|\n||domain.net^$badoption")
	f.Write(data)

	// Load from file
	ruleSet, err := NewRulesSetFromFile(path)
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
}

func TestRuleWithScriptOption(t *testing.T) {
	rules := []string{"||ads.example.com^$script"}
	ruleSet, err := NewRuleSetFromStr(rules)
	assert.NoError(t, err)
	assert.True(t, ruleSet.rulesOptionsString["script"] != ``)
}

func TestRuleWithImageOption(t *testing.T) {
	rules := []string{"/banner/*/img^$image"}
	ruleSet, err := NewRuleSetFromStr(rules)
	assert.NoError(t, err)
	assert.True(t, ruleSet.rulesOptionsString["image"] != ``)
}

func TestRuleSetWithStyleSheetOption(t *testing.T) {
	rules := []string{"||ads.example.com^$stylesheet"}
	ruleSet, err := NewRuleSetFromStr(rules)
	assert.NoError(t, err)
	assert.True(t, ruleSet.Match(reqFromURL("http://ads.example.com/banner/foo/file.css")))
}

func TestExtractOptionsFromRequest(t *testing.T) {
	reqUrl, _ := url.ParseRequestURI("http://example.com/banner/foo/file.js")
	req := Request{
		URL:     reqUrl,
		Origin:  "",
		Referer: "anything",
		IsXHR:   false,
	}
	options := extractOptionsFromRequest(req)
	assert.True(t, options["script"])
	assert.True(t, options["thirdparty"])
	assert.False(t, options["image"])
	assert.False(t, options["stylesheet"])
	assert.False(t, options["font"])
}
