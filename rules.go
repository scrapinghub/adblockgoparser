package adblockgoparser

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	ErrSkipComment     = errors.New("Commented rules are skipped")
	ErrSkipHTML        = errors.New("HTML rules are skipped")
	ErrEmptyLine       = errors.New("Empty lines are skipped")
	ErrUnsupportedRule = errors.New("Unsupported option rules are skipped")
	ErrCompilingRegex  = errors.New("Error compiling regexp")
	// Except domain
	supportedOptions = []string{
		"image",
		"script",
		"stylesheet",
		"font",
		"third-party",
		"xmlhttprequest",
	}
	supportedOptionsPat = func() map[string]struct{} {
		rv := map[string]struct{}{}
		for _, key := range supportedOptions {
			rv[key] = struct{}{}
		}
		return rv
	}()
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

const (
	addressPart = iota
	domainName
	exactAddress
)

type ruleAdBlock struct {
	ruleText    string
	regex       *regexp.Regexp
	options     map[string]bool
	isException bool
	domains     map[string]bool
	ruleType    int
}

func ParseRule(ruleText string) (*ruleAdBlock, error) {
	rule := &ruleAdBlock{
		ruleText: strings.TrimSpace(ruleText),
		domains:  map[string]bool{},
		options:  map[string]bool{},
	}

	if rule.ruleText == "" {
		return nil, ErrEmptyLine
	}

	if strings.HasPrefix(rule.ruleText, "!") || strings.HasPrefix(rule.ruleText, "[Adblock") {
		return nil, ErrSkipComment
	}

	if strings.Contains(rule.ruleText, "##") || strings.Contains(rule.ruleText, "#@#") || strings.Contains(rule.ruleText, "#?#") {
		return nil, ErrSkipHTML
	}

	rule.isException = strings.HasPrefix(rule.ruleText, "@@")
	if rule.isException {
		rule.ruleText = rule.ruleText[2:]
	}

	if strings.Contains(rule.ruleText, "$") {
		parts := strings.SplitN(rule.ruleText, "$", 2)
		rule.ruleText = parts[0]

		for _, option := range strings.Split(parts[1], ",") {
			optionNegative := !strings.HasPrefix(option, "~")
			option = strings.TrimPrefix(option, "~")
			_, supportedOption := supportedOptionsPat[option]

			switch {
			case strings.HasPrefix(option, "domain="):
				for _, domain := range strings.Split(option[len("domain="):], "|") {
					name := strings.TrimSpace(domain)
					rule.domains[strings.TrimPrefix(name, "~")] = !strings.HasPrefix(name, "~")
				}
			case !supportedOption:
				return nil, ErrUnsupportedRule
			default:
				rule.options[option] = optionNegative
			}
		}
	}

	rule.ruleType = addressPart
	if strings.HasPrefix(rule.ruleText, "||") && strings.HasSuffix(rule.ruleText, "^") {
		domain := rule.ruleText
		domain = strings.TrimPrefix(domain, "||")
		domain = strings.TrimSuffix(domain, "^")
		rule.domains[domain] = true
		rule.ruleType = domainName
	}

	if strings.HasPrefix(rule.ruleText, "|") && strings.HasSuffix(rule.ruleText, "|") {
		rule.ruleType = exactAddress
	}

	re, err := regexp.Compile(ruleToRegexp(rule.ruleText))
	if err != nil {
		return nil, ErrCompilingRegex
	}
	rule.regex = re
	return rule, nil
}

type RuleSet struct {
	white *Matcher
	black *Matcher
}

func (ruleSet *RuleSet) Allow(req *Request) bool {
	return ruleSet.white.Match(req) || !ruleSet.black.Match(req)
}

func NewRuleSetFromList(rulesStr []string) (*RuleSet, error) {
	ruleSet := &RuleSet{
		white: &Matcher{next: map[rune]*Matcher{}},
		black: &Matcher{next: map[rune]*Matcher{}},
	}
	// Start parsing
	for _, ruleStr := range rulesStr {
		rule, err := ParseRule(ruleStr)
		switch {
		case err == nil:
			if !rule.isException {
				ruleSet.black.add(rule)
			}
			if rule.isException {
				ruleSet.white.add(rule)
			}
		case errors.Is(err, ErrSkipComment),
			errors.Is(err, ErrSkipHTML),
			errors.Is(err, ErrUnsupportedRule),
			errors.Is(err, ErrEmptyLine):
			return nil, fmt.Errorf("%w: %s", err, ruleStr)
		default:
			return nil, fmt.Errorf("Cannot parse rule: %w", err)
		}
	}
	return ruleSet, nil
}

func ruleToRegexp(text string) string {
	// Convert AdBlock rule to a regular expression.
	if text == "" {
		return ".*"
	}

	// Check if the rule isn't already regexp
	length := len(text)
	if length >= 2 && text[:1] == "/" && text[length-1:] == "/" {
		return text[1 : length-1]
	}

	// escape special regex characters
	rule := text
	rule = regexp.QuoteMeta(rule)

	// |, ^ and * should not be escaped
	rule = strings.ReplaceAll(rule, `\|`, `|`)
	rule = strings.ReplaceAll(rule, `\^`, `^`)
	rule = strings.ReplaceAll(rule, `\*`, `*`)

	// XXX: the resulting regex must use non-capturing groups (?:
	// for performance reasons; also, there is a limit on number
	// of capturing groups, no using them would prevent building
	// a single regex out of several rules.

	// Separator character ^ matches anything but a letter, a digit, or
	// one of the following: _ - . %. The end of the address is also
	// accepted as separator.
	rule = strings.ReplaceAll(rule, "^", `(?:[^\w\d_\\\-.%]|$)`)

	// * symbol
	rule = strings.ReplaceAll(rule, "*", ".*")

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
			rule = `^(?:[^:/?#]+:)?(?://(?:[^/?#]*\.)?)?` + rule[2:]
		}
	} else if rule[0] == '|' {
		// | in the beginning means start of the address
		rule = "^" + rule[1:]
	}

	// other | symbols should be escaped
	// we have "|$" in our regexp - do not touch it
	rule = regexp.MustCompile(`(\|)[^$]`).ReplaceAllString(rule, `\|`)
	return rule
}

func extractOptionsFromRequest(req *Request) map[string]bool {
	result := make(map[string]bool, len(supportedOptions))
	result["xmlhttprequest"] = req.IsXHR

	path := strings.ToLower(req.URL.Path)
	if strings.HasSuffix(path, ".gz") {
		path = path[:len(path)-len(".gz")]
	}

	switch filepath.Ext(path) {
	case ".js":
		result["script"] = true
	case ".jpg", ".jpeg", ".png", ".gif", ".webp", ".tiff", ".psd", ".raw", ".bmp", ".heif", ".indd", ".jpeg2000":
		result["image"] = true
	case ".css":
		result["stylesheet"] = true
	case ".otf", ".ttf", ".fnt":
		result["font"] = true
	}

	refererUrl, err := url.ParseRequestURI(req.Origin)
	if err == nil {
		result["third-party"] = refererUrl.Hostname() != req.URL.Hostname()
	}
	return result
}
