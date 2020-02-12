package main

import (
	"testing"
)

func TestCommentRule(t *testing.T) {
	ruleText := "! Title: EasyList"
	rule, err := ParseRule(ruleText)
	if err != nil {
		t.Error("cannot parse")
	}
	if rule.isComment != true {
		t.Error("isComment should be true")
	}
	if rule.isHTMLRule != false {
		t.Error("isHTMLRule should be false")
	}
	if rule.isException != false {
		t.Error("isException should be false")
	}
	if rule.ruleText != ruleText {
		t.Errorf("ruleText should be %v", ruleText)
	}

	ruleText = "[Adblock Plus 2.0]"
	rule, err = ParseRule("[Adblock Plus 2.0]")
	if err != nil {
		t.Error("cannot parse")
	}
	if rule.isComment != true {
		t.Error("isComment should be true")
	}
	if rule.isHTMLRule != false {
		t.Error("isHTMLRule should be false")
	}
	if rule.isException != false {
		t.Error("isException should be false")
	}
	if rule.ruleText != ruleText {
		t.Errorf("ruleText should be %v", ruleText)
	}
}

func TestHTMLRule(t *testing.T) {

	ruleText := "###AdSense1"
	rule, err := ParseRule(ruleText)
	if err != nil {
		t.Error("cannot parse")
	}
	if rule.isComment != false {
		t.Error("isComment should be false")
	}
	if rule.isHTMLRule != true {
		t.Error("isHTMLRule should be true")
	}
	if rule.isException != false {
		t.Error("isException should be false")
	}
	if rule.ruleText != ruleText {
		t.Errorf("ruleText should be %v", ruleText)
	}

	ruleText = "statejournal.com#@##WNAd41"
	rule, err = ParseRule(ruleText)
	if err != nil {
		t.Error("cannot parse")
	}
	if rule.isComment != false {
		t.Error("isComment should be false")
	}
	if rule.isHTMLRule != true {
		t.Error("isHTMLRule should be true")
	}
	if rule.isException != false {
		t.Error("isException should be false")
	}
	if rule.ruleText != ruleText {
		t.Errorf("ruleText should be %v", ruleText)
	}

}

func TestExceptionRule(t *testing.T) {
	ruleText := "@@||akamaized.net^$domain=kora-online.tv"
	rule, err := ParseRule(ruleText)
	if err != nil {
		t.Error("cannot parse")
	}
	if rule.isComment != false {
		t.Error("isComment should be false")
	}
	if rule.isHTMLRule != false {
		t.Error("isHTMLRule should be false")
	}
	if rule.isException != true {
		t.Error("isException should be true")
	}
	expected := "||akamaized.net^"
	if rule.ruleText != expected {
		t.Errorf("ruleText should be %v", expected)
	}
}

func TestRuleBlockingAddressPart(t *testing.T) {
	ruleText := "/banner/*/img^"
	rule, err := ParseRule(ruleText)
	if err != nil {
		t.Error("cannot parse")
	}
	// TODO: Change url to Request
	url := "http://example.com/banner/foo/img"
	if rule.Allow(url) != false {
		t.Errorf("%v should not allow %v", ruleText, url)
	}
	url = "http://example.com/banner/foo/bar/img?param"
	if rule.Allow(url) != false {
		t.Errorf("%v should not allow %v", ruleText, url)
	}
	url = "http://example.com/banner//img/foo"
	if rule.Allow(url) != false {
		t.Errorf("%v should not allow %v", ruleText, url)
	}

	url = "http://example.com/banner/img"
	if rule.Allow(url) != true {
		t.Errorf("%v should allow %v", ruleText, url)
	}
	url = "http://example.com/banner/foo/imgraph"
	if rule.Allow(url) != true {
		t.Errorf("%v should allow %v", ruleText, url)
	}
	url = "http://example.com/banner/foo/img.gif"
	if rule.Allow(url) != true {
		t.Errorf("%v should allow %v", ruleText, url)
	}
}

func TestRuleBlockingDomainName(t *testing.T) {
	ruleText := "||ads.example.com^"
	rule, err := ParseRule(ruleText)
	if err != nil {
		t.Error("cannot parse")
	}
	// TODO: Change url to Request
	url := "http://ads.example.com/foo.gif"
	if rule.Allow(url) != false {
		t.Errorf("%v should not allow %v", ruleText, url)
	}
	url = "http://server1.ads.example.com/foo.gif"
	if rule.Allow(url) != false {
		t.Errorf("%v should not allow %v", ruleText, url)
	}
	url = "https://ads.example.com:8000/"
	if rule.Allow(url) != false {
		t.Errorf("%v should not allow %v", ruleText, url)
	}

	url = "http://ads.example.com.ua/foo.gif"
	if rule.Allow(url) != true {
		t.Errorf("%v should allow %v", ruleText, url)
	}
	url = "http://example.com/redirect/http://ads.example.com/"
	if rule.Allow(url) != true {
		t.Errorf("%v should allow %v", ruleText, url)
	}
}

func TestRuleBlockingExactAddress(t *testing.T) {
	ruleText := "|http://example.com/|"
	rule, err := ParseRule(ruleText)
	if err != nil {
		t.Error("cannot parse")
	}
	// TODO: Change url to Request
	url := "http://example.com/"
	if rule.Allow(url) != false {
		t.Errorf("%v should not allow %v", ruleText, url)
	}

	url = "http://example.com/foo.gif"
	if rule.Allow(url) != true {
		t.Errorf("%v should allow %v", ruleText, url)
	}

	url = "http://example.info/redirect/http://example.com/"
	if rule.Allow(url) != true {
		t.Errorf("%v should allow %v", ruleText, url)
	}
}
