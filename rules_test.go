package adblockgoparser

import (
	"net/url"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCommentRule(t *testing.T) {
	ruleText := "[Adblock Plus 2.0]"
	rules := []string{ruleText}
	_, err := NewRuleSetFromStr(rules)
	assert.NoError(t, err)

	ruleText = "! Title: EasyList"
	rules = []string{ruleText}
	_, err = NewRuleSetFromStr(rules)
	assert.NoError(t, err)
}

func TestHTMLRule(t *testing.T) {
	ruleText := "###AdSense1"
	rules := []string{ruleText}
	_, err := NewRuleSetFromStr(rules)
	assert.NoError(t, err)

	ruleText = "statejournal.com#@##WNAd41"
	rules = []string{ruleText}
	_, err = NewRuleSetFromStr(rules)
	assert.NoError(t, err)
}

func TestExceptionRule(t *testing.T) {
	ruleText := "@@||domain.net^$domain=otherdomain.net"
	rules := []string{ruleText}
	ruleSet, err := NewRuleSetFromStr(rules)
	assert.NoError(t, err)
	assert.NotEmpty(t, ruleSet.regexBasicWhitelist)
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
	data := []byte(`
		[Adblock comment
		!Other comment
		anyhtmlrule.com#@##AdImage
		/banner/*/img^
		||ads.example.com^
		|http://example.com/|
		||domain.net^$badoption
	`)
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

	// Now add some exceptions
	data = []byte(`
		[Adblock comment
		!Other comment
		anyhtmlrule.com#@##AdImage
		/banner/*/img^
		||ads.example.com^
		|http://example.com/|
		||domain.net^$badoption
		@@/banner/*/img^
		@@||ads.example.com^
		@@|http://example.com/|
	`)
	f.Write(data)

	// Load from file
	ruleSet, err = NewRulesSetFromFile(path)
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
	ruleSet, err := NewRuleSetFromStr(rules)
	assert.NoError(t, err)
	assert.True(t, ruleSet.stringBlacklistIncludeOptions["script"] != ``)
	assert.True(t, ruleSet.stringBlacklistExcludeOptions["script"] == ``)
	assert.True(t, ruleSet.Allow(reqFromURL("http://ads.example.com/")))
	assert.False(t, ruleSet.Allow(reqFromURL("http://ads.example.com/file.js")))

	// Only allow script
	rules = []string{"||ads.example.com^$~script"}
	ruleSet, err = NewRuleSetFromStr(rules)
	assert.NoError(t, err)
	assert.True(t, ruleSet.stringBlacklistIncludeOptions["script"] == ``)
	assert.True(t, ruleSet.stringBlacklistExcludeOptions["script"] != ``)
	assert.False(t, ruleSet.Allow(reqFromURL("http://ads.example.com/")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://ads.example.com/file.js")))

}

func TestRuleWithScriptOptionOnWhitelist(t *testing.T) {
	// Block everything on ads.example.com domain, execept if it is script
	rules := []string{"||ads.example.com^", "@@||ads.example.com^$script"}
	ruleSet, err := NewRuleSetFromStr(rules)
	assert.NoError(t, err)
	assert.True(t, ruleSet.stringBlacklistIncludeOptions["script"] == ``)
	assert.True(t, ruleSet.stringBlacklistExcludeOptions["script"] == ``)
	assert.True(t, ruleSet.stringWhitelistIncludeOptions["script"] != ``)
	assert.True(t, ruleSet.stringWhitelistExcludeOptions["script"] == ``)
	assert.False(t, ruleSet.Allow(reqFromURL("http://ads.example.com/")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://ads.example.com/file.js")))

	// Block everything on ads.example.com domain, execept if it is not script
	rules = []string{"||ads.example.com^", "@@||ads.example.com^$~script"}
	ruleSet, err = NewRuleSetFromStr(rules)
	assert.NoError(t, err)
	assert.True(t, ruleSet.stringBlacklistIncludeOptions["script"] == ``)
	assert.True(t, ruleSet.stringBlacklistExcludeOptions["script"] == ``)
	assert.True(t, ruleSet.stringWhitelistIncludeOptions["script"] == ``)
	assert.True(t, ruleSet.stringWhitelistExcludeOptions["script"] != ``)
	assert.True(t, ruleSet.Allow(reqFromURL("http://ads.example.com/")))
	assert.False(t, ruleSet.Allow(reqFromURL("http://ads.example.com/file.js")))
}

func TestRuleWithDomainOption(t *testing.T) {
	// Block everything on ads.example.com domain, execept if it is script
	rules := []string{"/banner/*/img$domain=example.com|~bar.example.com"}
	ruleSet, err := NewRuleSetFromStr(rules)
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

func TestRuleWithImageOption(t *testing.T) {
	rules := []string{"/banner/*/img^$image"}
	ruleSet, err := NewRuleSetFromStr(rules)
	assert.NoError(t, err)
	assert.True(t, ruleSet.stringBlacklistIncludeOptions["image"] != ``)
}

func TestRuleSetWithStyleSheetOption(t *testing.T) {
	rules := []string{"||ads.example.com^$stylesheet"}
	ruleSet, err := NewRuleSetFromStr(rules)
	assert.NoError(t, err)
	assert.False(t, ruleSet.Allow(reqFromURL("http://ads.example.com/banner/foo/file.css")))
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
	assert.False(t, options["xmlhttprequest"])
}
