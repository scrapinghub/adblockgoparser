package main

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

var (
	binaryOptions = []string{
		"document",
		"domain",
		"elemhide",
		"font",
		"genericblock",
		"generichide",
		"image",
		"matchcase",
		"media",
		"object",
		"other",
		"ping",
		"popup",
		"script",
		"stylesheet",
		"subdocument",
		"thirdparty",
		"webrtc",
		"websocket",
		"xmlhttprequest",
	}
	// optionsSplitPat    = fmt.Sprintf(",(?=~?(?:%v))", strings.Join(binaryOptions, "|"))
	optionsSplitPat    = fmt.Sprintf(",(~?(?:%v))", strings.Join(binaryOptions, "|"))
	optionsSplitRe     = regexp.MustCompile(optionsSplitPat)
	escapeSpecialRegxp = regexp.MustCompile(`([.$+?{}()\[\]\\])`)
)

// Structs

type Request struct {
	// parsed full URL of the request
	URL *url.URL
	// a value of Origin header
	Origin string
	// a value of Referer header
	Referer string
	// Defines is request looks like XHLHttpRequest
	IsXHR bool
}

type Rule struct {
	raw         string
	ruleText    string
	rawOptions  []string
	regexString string
	options     map[string]bool
	optionsKeys []string
	isComment   bool
	isHTMLRule  bool
	isException bool
	document    bool
	domain      map[string]bool
}

// Interfaces

type RuleSet interface {
	Allow(*Request) bool
}

// Allow methods

func (rule *Rule) Allow(url string) bool {
	// TODO
	return false
}

//

func ParseRule(ruleText string) (*Rule, error) {
	rule := &Rule{}
	rule.raw = ruleText
	ruleText = strings.TrimSpace(ruleText)
	rule.isComment = strings.Contains(ruleText, "!") || strings.Contains(ruleText, "[Adblock")
	if rule.isComment {
		rule.isHTMLRule = false
		rule.isException = false
	} else {
		rule.isHTMLRule = strings.Contains(ruleText, "##") || strings.Contains(ruleText, "#@#")
		rule.isException = strings.HasPrefix(ruleText, "@@")
		if rule.isException {
			ruleText = ruleText[2:]
		}
	}

	rule.options = make(map[string]bool)
	if !rule.isComment && strings.Contains(ruleText, "$") {
		var option string
		parts := strings.SplitN(ruleText, "$", 2)
		length := len(parts)
		if length > 0 {
			ruleText = parts[0]
		}
		if length > 1 {
			option = parts[1]
		}

		rule.rawOptions = strings.Split(option, ",")
		for _, opt := range rule.rawOptions {
			if strings.HasPrefix(opt, "domain=") {
				rule.domain = parseDomainOption(opt)
			} else {
				rule.options[strings.TrimPrefix(opt, "~")] = !strings.HasPrefix(opt, "~")
			}
		}
	} else {
		rule.rawOptions = []string{}
		rule.domain = make(map[string]bool)
	}

	rule.optionsKeys = rule.OptionsKeys()
	rule.ruleText = ruleText

	if rule.isComment || rule.isHTMLRule {
		rule.regexString = ""
	} else {
		var err error
		rule.regexString, err = ruleToRegexp(ruleText)
		if err != nil {
			return nil, err
		}
	}
	return rule, nil
}

func NewRuleSet(rules []*Rule) (RuleSet, error) {
	return nil, nil
}

func (rule *Rule) OptionsKeys() []string {
	opts := []string{}
	for opt := range rule.options {
		opts = append(opts, opt)
	}
	if rule.domain != nil && len(rule.domain) >= 0 {
		opts = append(opts, "domain")
	}
	return opts
}

func parseDomainOption(text string) map[string]bool {
	domains := text[len("domain="):]
	parts := strings.Split(strings.Replace(domains, ",", "|", -1), "|")
	opts := make(map[string]bool, len(parts))
	for _, part := range parts {
		opts[strings.TrimPrefix(part, "~")] = !strings.HasPrefix(part, "~")
	}
	return opts
}

func ruleToRegexp(text string) (string, error) {
	// Convert AdBlock rule to a regular expression.
	if text == "" {
		return ".*", nil
	}

	// Check if the rule isn't already regexp
	length := len(text)
	if length >= 2 && text[:1] == "/" && text[length-1:] == "/" {
		return text[1 : length-1], nil
	}

	// escape special regex characters
	rule := escapeSpecialRegxp.ReplaceAllStringFunc(text, func(src string) string {
		return fmt.Sprintf(`\%v`, src)
	})

	// XXX: the resulting regex must use non-capturing groups (?:
	// for performance reasons; also, there is a limit on number
	// of capturing groups, no using them would prevent building
	// a single regex out of several rules.

	// Separator character ^ matches anything but a letter, a digit, or
	// one of the following: _ - . %. The end of the address is also
	// accepted as separator.
	rule = strings.Replace(rule, "^", `(?:[^\\w\\d_\\\-.%]|$)`, -1)

	// * symbol
	rule = strings.Replace(rule, "*", ".*", -1)

	// | in the end means the end of the address
	length = len(rule)
	if rule[length-1] == '|' {
		rule = rule[:length-1] + "$"
	}

	// || in the beginning means beginning of the domain name
	if rule[:2] == "||" {
		// XXX: it is better to use urlparse for such things,
		// but urlparse doesn't give us a single regex.
		// Regex is based on http://tools.ietf.org/html/rfc3986#appendix-B
		if len(rule) > 2 {
			//       |            | complete part       |
			//       |  scheme    | of the domain       |
			rule = `^(?:[^:/?#]+:)?(?://(?:[^/?#]*\\.)?)?` + rule[2:]
		}
	} else if rule[0] == '|' {
		// | in the beginning means start of the address
		rule = "^" + rule[1:]
	}

	// other | symbols should be escaped
	// we have "|$" in our regexp - do not touch it
	rule = regexp.MustCompile(`(\|)[^$]`).ReplaceAllString(rule, `\|`)

	return rule, nil
}
