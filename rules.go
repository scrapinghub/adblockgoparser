package adblockgoparser

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/google/logger"
)

var (
	ErrSkipComment     = errors.New("Commented rules are skipped")
	ErrSkipHTML        = errors.New("HTML rules are skipped")
	ErrEmptyLine       = errors.New("Empty lines are skipped")
	ErrUnsupportedRule = errors.New("Unsupported option rules are skipped")
	binaryOptions      = []string{
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
	optionsSplitPat = fmt.Sprintf(",(~?(?:%v))", strings.Join(binaryOptions, "|"))
	optionsSplitRe  = regexp.MustCompile(optionsSplitPat)
	// Except domain
	supportedOptions = []string{
		"image",
		"script",
		"stylesheet",
		"font",
		"thirdparty",
		"xmlhttprequest",
	}
	supportedOptionsPat = strings.Join(supportedOptions, ",")
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

type ruleAdBlock struct {
	raw         string
	ruleText    string
	regexString string
	regex       *regexp.Regexp
	options     map[string]bool
	isException bool
	domains     map[string]bool
}

func parseRule(ruleText string) (*ruleAdBlock, error) {
	if strings.TrimSpace(ruleText) == "" {
		return nil, ErrEmptyLine
	}
	rule := &ruleAdBlock{
		domains:  map[string]bool{},
		options:  map[string]bool{},
		raw:      ruleText,
		ruleText: strings.TrimSpace(ruleText),
	}

	isComment := strings.Contains(rule.ruleText, "!") || strings.Contains(rule.ruleText, "[Adblock")
	if isComment {
		return nil, ErrSkipComment
	}

	isHTMLRule := strings.Contains(rule.ruleText, "##") || strings.Contains(rule.ruleText, "#@#")
	if isHTMLRule {
		return nil, ErrSkipHTML
	}

	rule.isException = strings.HasPrefix(rule.ruleText, "@@")
	if rule.isException {
		rule.ruleText = rule.ruleText[2:]
	}

	if strings.Contains(rule.ruleText, "$") {
		parts := strings.SplitN(rule.ruleText, "$", 2)
		length := len(parts)

		if length > 0 {
			rule.ruleText = parts[0]
		}

		if length > 1 {
			for _, option := range strings.Split(parts[1], ",") {
				if strings.HasPrefix(option, "domain=") {
					rule.domains = parseDomainOption(option)
				} else {
					optionName := strings.TrimPrefix(option, "~")
					if ok := strings.Contains(supportedOptionsPat, optionName); !ok {
						return nil, ErrUnsupportedRule
					}
					rule.options[optionName] = !strings.HasPrefix(option, "~")
				}
			}
		}
	}

	rule.regexString = ruleToRegexp(rule.ruleText)

	return rule, nil
}

type RuleSet struct {
	whitelist      []*ruleAdBlock
	whitelistRegex *regexp.Regexp
	blacklist      []*ruleAdBlock
	blacklistRegex *regexp.Regexp

	whitelistDomainsNoOptions   []*ruleAdBlock
	whitelistDomainsWithOptions []*ruleAdBlock
	blacklistDomainsNoOptions   []*ruleAdBlock
	blacklistDomainsWithOptions []*ruleAdBlock

	whitelistIncludeOptions map[string][]*ruleAdBlock
	whitelistExcludeOptions map[string][]*ruleAdBlock
	blacklistIncludeOptions map[string][]*ruleAdBlock
	blacklistExcludeOptions map[string][]*ruleAdBlock
}

func matchWhite(ruleSet RuleSet, req Request) bool {
	if ruleSet.whitelistRegex != nil && ruleSet.whitelistRegex.MatchString(req.URL.String()) {
		return true
	}

	rules := []*ruleAdBlock{}
	for _, rule := range ruleSet.whitelistDomainsNoOptions {
		include := true
		matched := false
		for domain, allowed := range rule.domains {
			if strings.Contains(req.URL.Hostname(), domain) {
				include = include && allowed
				matched = true
			}
		}
		if matched && include {
			rules = append(rules, rule)
		}
	}

	whitelistDomainsRegex := CombinedRegex(rules)
	if whitelistDomainsRegex != nil && whitelistDomainsRegex.MatchString(req.URL.String()) {
		return true
	}

	rules = []*ruleAdBlock{}
	for _, rule := range ruleSet.whitelistDomainsWithOptions {
		include := true
		matched := false
		for domain, allowed := range rule.domains {
			if strings.Contains(req.URL.Hostname(), domain) {
				include = include && allowed
				matched = true
			}
		}
		if matched && include {
			rules = append(rules, rule)
		}
	}
	includeOptionsRegex := map[string]*regexp.Regexp{}
	excludeOptionsRegex := map[string]*regexp.Regexp{}

	includeOptionsRegex, excludeOptionsRegex = addRulesToOptions(rules, ruleSet.whitelistIncludeOptions, ruleSet.whitelistExcludeOptions)
	options := extractOptionsFromRequest(req)

	for option, active := range options {
		if includeOptionsRegex[option] != nil && includeOptionsRegex[option].MatchString(req.URL.String()) {
			return active == true
		}
		if excludeOptionsRegex[option] != nil && excludeOptionsRegex[option].MatchString(req.URL.String()) {
			return active == false
		}
	}
	return false
}

func matchBlack(ruleSet RuleSet, req Request) bool {
	if ruleSet.blacklistRegex != nil && ruleSet.blacklistRegex.MatchString(req.URL.String()) {
		return true
	}

	rules := []*ruleAdBlock{}
	for _, rule := range ruleSet.blacklistDomainsNoOptions {
		include := true
		matched := false
		for domain, allowed := range rule.domains {
			if strings.Contains(req.URL.Hostname(), domain) {
				include = include && allowed
				matched = true
			}
		}
		if matched && include {
			rules = append(rules, rule)
		}
	}

	blacklistDomainsRegex := CombinedRegex(rules)
	if blacklistDomainsRegex != nil && blacklistDomainsRegex.MatchString(req.URL.String()) {
		return true
	}

	rules = []*ruleAdBlock{}
	for _, rule := range ruleSet.blacklistDomainsWithOptions {
		include := true
		matched := false
		for domain, allowed := range rule.domains {
			if strings.Contains(req.URL.Hostname(), domain) {
				include = include && allowed
				matched = true
			}
		}
		if matched && include {
			rules = append(rules, rule)
		}
	}
	includeOptionsRegex := map[string]*regexp.Regexp{}
	excludeOptionsRegex := map[string]*regexp.Regexp{}

	includeOptionsRegex, excludeOptionsRegex = addRulesToOptions(rules, ruleSet.blacklistIncludeOptions, ruleSet.blacklistExcludeOptions)
	options := extractOptionsFromRequest(req)
	for option, active := range options {
		if includeOptionsRegex[option] != nil && includeOptionsRegex[option].MatchString(req.URL.String()) {
			return active == true
		}
		if excludeOptionsRegex[option] != nil && excludeOptionsRegex[option].MatchString(req.URL.String()) {
			return active == false
		}
	}
	return false
}

func addRulesToOptions(rules []*ruleAdBlock, includeOptions map[string][]*ruleAdBlock, excludeOptions map[string][]*ruleAdBlock) (map[string]*regexp.Regexp, map[string]*regexp.Regexp) {
	include := map[string][]*ruleAdBlock{}
	exclude := map[string][]*ruleAdBlock{}

	for _, rule := range rules {
		for option, allowed := range rule.options {
			if allowed {
				include[option] = append(include[option], rule)
			} else {
				exclude[option] = append(exclude[option], rule)
			}
		}
	}

	// Append from rule with option but withour domains
	for option, rule := range includeOptions {
		include[option] = append(include[option], rule...)
	}
	for option, rule := range excludeOptions {
		exclude[option] = append(exclude[option], rule...)
	}

	includeRegex := map[string]*regexp.Regexp{}
	excludeRegex := map[string]*regexp.Regexp{}
	for option, _ := range include {
		includeRegex[option] = CombinedRegex(include[option])
	}
	for option, _ := range exclude {
		excludeRegex[option] = CombinedRegex(exclude[option])
	}

	return includeRegex, excludeRegex
}

func (ruleSet *RuleSet) Allow(req Request) bool {
	if ok := matchWhite(*ruleSet, req); ok {
		return true
	}
	if ok := matchBlack(*ruleSet, req); ok {
		return false
	}
	return true
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)

	if err != nil {
		return nil, err
	}
	defer f.Close()

	reader := bufio.NewReader(f)
	lines := []string{}
	for line := []byte{}; err == nil; line, _, err = reader.ReadLine() {
		sl := strings.TrimSuffix(string(line), "\n\r")
		if len(sl) == 0 {
			continue
		}
		lines = append(lines, sl)
	}

	return lines, nil
}

func NewRulesSetFromFile(path string) (*RuleSet, error) {
	lines, err := readLines(path)
	if err != nil {
		return nil, err
	}
	return NewRuleSetFromStr(lines)
}

func NewRuleSetFromStr(rulesStr []string) (*RuleSet, error) {
	logger.Init("NewRuleSetFromStr", true, true, ioutil.Discard)
	logger.SetFlags(log.LstdFlags)

	ruleSet := &RuleSet{
		whitelistIncludeOptions: map[string][]*ruleAdBlock{},
		whitelistExcludeOptions: map[string][]*ruleAdBlock{},
		blacklistIncludeOptions: map[string][]*ruleAdBlock{},
		blacklistExcludeOptions: map[string][]*ruleAdBlock{},
	}

	// Start parsing
	for _, ruleStr := range rulesStr {
		rule, err := parseRule(ruleStr)
		switch {
		case err == nil:
			// Blacklist without options nor domain filter
			if !rule.isException && len(rule.domains) == 0 && len(rule.options) == 0 {
				ruleSet.blacklist = append(ruleSet.blacklist, rule)
				continue
			}
			// Whitelist without options nor domain filter
			if rule.isException && len(rule.domains) == 0 && len(rule.options) == 0 {
				ruleSet.whitelist = append(ruleSet.whitelist, rule)
				continue
			}
			// Blacklist without options with domain filter
			if !rule.isException && len(rule.domains) > 0 && len(rule.options) == 0 {
				ruleSet.blacklistDomainsNoOptions = append(ruleSet.blacklistDomainsNoOptions, rule)
				continue
			}
			// Whitelist without options with domain filter
			if rule.isException && len(rule.domains) > 0 && len(rule.options) == 0 {
				ruleSet.whitelistDomainsNoOptions = append(ruleSet.whitelistDomainsNoOptions, rule)
				continue
			}
			// Blacklist with options with domain filter
			if !rule.isException && len(rule.domains) > 0 && len(rule.options) >= 0 {
				ruleSet.blacklistDomainsWithOptions = append(ruleSet.blacklistDomainsWithOptions, rule)
				continue
			}
			// Whitelist with options with domain filter
			if rule.isException && len(rule.domains) > 0 && len(rule.options) >= 0 {
				ruleSet.whitelistDomainsWithOptions = append(ruleSet.whitelistDomainsWithOptions, rule)
				continue
			}
			// Blacklist with options without domain filter
			if !rule.isException && len(rule.domains) == 0 && len(rule.options) > 0 {
				for option, allowed := range rule.options {
					if allowed {
						ruleSet.blacklistIncludeOptions[option] = append(ruleSet.blacklistIncludeOptions[option], rule)
					} else {
						ruleSet.blacklistExcludeOptions[option] = append(ruleSet.blacklistExcludeOptions[option], rule)
					}
				}
				continue
			}
			// Whitelist with options without domain filter
			if rule.isException && len(rule.domains) == 0 && len(rule.options) > 0 {
				for option, allowed := range rule.options {
					if allowed {
						ruleSet.whitelistIncludeOptions[option] = append(ruleSet.whitelistIncludeOptions[option], rule)
					} else {
						ruleSet.whitelistExcludeOptions[option] = append(ruleSet.whitelistExcludeOptions[option], rule)
					}
				}
				continue
			}
		case errors.Is(err, ErrSkipComment),
			errors.Is(err, ErrSkipHTML),
			errors.Is(err, ErrUnsupportedRule):
			logger.Info(err, ": ", strings.TrimSpace(ruleStr))
		case errors.Is(err, ErrEmptyLine):
			logger.Info(err)
		default:
			logger.Info("cannot parse rule: ", err)
			return nil, fmt.Errorf("cannot parse rule: %w", err)
		}
	}
	ruleSet.whitelistRegex = CombinedRegex(ruleSet.whitelist)
	ruleSet.blacklistRegex = CombinedRegex(ruleSet.blacklist)

	return ruleSet, nil
}

func CombinedRegex(rules []*ruleAdBlock) *regexp.Regexp {
	regexes := []string{}
	for _, rule := range rules {
		regexes = append(regexes, rule.regexString)
	}
	rs := strings.Join(regexes, "|")
	if rs == "" {
		return nil
	}
	return regexp.MustCompile(rs)
}

func parseDomainOption(text string) map[string]bool {
	domains := text[len("domain="):]
	parts := strings.Split(domains, "|")
	opts := make(map[string]bool, len(parts))

	for _, part := range parts {
		opts[strings.TrimPrefix(part, "~")] = !strings.HasPrefix(part, "~")
	}

	return opts
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

func extractOptionsFromRequest(req Request) map[string]bool {
	result := make(map[string]bool, len(supportedOptions))

	filename := path.Base(req.URL.Path)
	result["script"] = regexp.MustCompile(`(?:\.js$|\.js\.gz$)`).MatchString(filename)
	result["image"] = regexp.MustCompile(`(?:\.jpg$|\.jpeg$|\.png$|\.gif$|\.webp$|\.tiff$|\.psd$|\.raw$|\.bmp$|\.heif$|\.indd$|\.jpeg2000$)`).MatchString(filename)
	result["stylesheet"] = regexp.MustCompile(`(?:\.css$)`).MatchString(filename)
	// More font extension at https://fileinfo.com/filetypes/font
	result["font"] = regexp.MustCompile(`(?:\.otf|\.ttf|\.fnt)`).MatchString(filename)
	result["thirdparty"] = req.Referer != ""
	result["xmlhttprequest"] = req.IsXHR

	return result
}
