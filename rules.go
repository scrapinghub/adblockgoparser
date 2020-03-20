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
	stringBasicWhitelist string
	regexBasicWhitelist  *regexp.Regexp

	stringBasicBlacklist string
	regexBasicBlacklist  *regexp.Regexp

	stringBlacklistIncludeOptions map[string]string
	regexBlacklistIncludeOptions  map[string]*regexp.Regexp

	stringBlacklistExcludeOptions map[string]string
	regexBlacklistExcludeOptions  map[string]*regexp.Regexp

	stringBlacklistIncludeDomains map[string]string
	regexBlacklistIncludeDomains  map[string]*regexp.Regexp

	stringBlacklistExcludeDomains map[string]string
	regexBlacklistExcludeDomains  map[string]*regexp.Regexp

	stringWhitelistIncludeOptions map[string]string
	regexWhitelistIncludeOptions  map[string]*regexp.Regexp

	stringWhitelistExcludeOptions map[string]string
	regexWhitelistExcludeOptions  map[string]*regexp.Regexp
}

func matchWhite(ruleSet RuleSet, req Request) bool {
	didMatch := false
	if ruleSet.stringBasicWhitelist != `` {
		didMatch = ruleSet.regexBasicWhitelist.MatchString(req.URL.String())
	}
	if didMatch {
		return true
	}

	options := extractOptionsFromRequest(req)
	for option, active := range options {
		if ruleSet.stringWhitelistIncludeOptions[option] != `` {
			didMatch = ruleSet.regexWhitelistIncludeOptions[option].MatchString(req.URL.String())
			if didMatch {
				return active == true
			}
		}
		if ruleSet.stringWhitelistExcludeOptions[option] != `` {
			didMatch = ruleSet.regexWhitelistExcludeOptions[option].MatchString(req.URL.String())
			if didMatch {
				return active == false
			}
		}
	}
	return false
}

func matchBlack(ruleSet RuleSet, req Request) bool {
	didMatch := false
	if ruleSet.stringBasicBlacklist != `` {
		didMatch = ruleSet.regexBasicBlacklist.MatchString(req.URL.String())
	}
	if didMatch {
		return true
	}

	disabledForDomain := false
	for domain := range ruleSet.stringBlacklistExcludeDomains {
		disabledForDomain = strings.Contains(req.URL.Hostname(), domain)
	}
	if !disabledForDomain {
		for domain := range ruleSet.stringBlacklistIncludeDomains {
			lookForDomain := strings.Contains(req.URL.Hostname(), domain)
			if lookForDomain && ruleSet.stringBlacklistIncludeDomains[domain] != `` {
				didMatch = ruleSet.regexBlacklistIncludeDomains[domain].MatchString(req.URL.String())
				if didMatch {
					return true
				}
			}
		}
	}

	options := extractOptionsFromRequest(req)
	for option, active := range options {
		if ruleSet.stringBlacklistIncludeOptions[option] != `` {
			didMatch = ruleSet.regexBlacklistIncludeOptions[option].MatchString(req.URL.String())
			if didMatch {
				return active == true
			}
		}
		if ruleSet.stringBlacklistExcludeOptions[option] != `` {
			didMatch = ruleSet.regexBlacklistExcludeOptions[option].MatchString(req.URL.String())
			if didMatch {
				return active == false
			}
		}
	}
	return false
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
		stringBlacklistIncludeOptions: map[string]string{},
		regexBlacklistIncludeOptions:  map[string]*regexp.Regexp{},

		stringBlacklistExcludeOptions: map[string]string{},
		regexBlacklistExcludeOptions:  map[string]*regexp.Regexp{},

		stringBlacklistIncludeDomains: map[string]string{},
		regexBlacklistIncludeDomains:  map[string]*regexp.Regexp{},

		stringBlacklistExcludeDomains: map[string]string{},
		regexBlacklistExcludeDomains:  map[string]*regexp.Regexp{},

		stringWhitelistIncludeOptions: map[string]string{},
		regexWhitelistIncludeOptions:  map[string]*regexp.Regexp{},

		stringWhitelistExcludeOptions: map[string]string{},
		regexWhitelistExcludeOptions:  map[string]*regexp.Regexp{},
	}

	// Start parsing
	for _, ruleStr := range rulesStr {
		rule, err := parseRule(ruleStr)

		switch {
		case err == nil:
			if len(rule.domains) > 0 && len(rule.options) == 0 {
				for domain, allowed := range rule.domains {
					if allowed {
						if ruleSet.stringBlacklistIncludeDomains[domain] == `` {
							ruleSet.stringBlacklistIncludeDomains[domain] = rule.regexString
						} else {
							ruleSet.stringBlacklistIncludeDomains[domain] = ruleSet.stringBlacklistIncludeDomains[domain] + `|` + rule.regexString
						}
					} else {
						if ruleSet.stringBlacklistExcludeDomains[domain] == `` {
							ruleSet.stringBlacklistExcludeDomains[domain] = rule.regexString
						} else {
							ruleSet.stringBlacklistExcludeDomains[domain] = ruleSet.stringBlacklistExcludeDomains[domain] + `|` + rule.regexString
						}
					}
				}
				continue
			}
			if len(rule.options) > 0 {
				if rule.isException {
					for option, allowed := range rule.options {
						if allowed {
							if ruleSet.stringWhitelistIncludeOptions[option] == `` {
								ruleSet.stringWhitelistIncludeOptions[option] = rule.regexString
							} else {
								ruleSet.stringWhitelistIncludeOptions[option] = ruleSet.stringWhitelistIncludeOptions[option] + `|` + rule.regexString
							}
						} else {
							if ruleSet.stringWhitelistExcludeOptions[option] == `` {
								ruleSet.stringWhitelistExcludeOptions[option] = rule.regexString
							} else {
								ruleSet.stringWhitelistExcludeOptions[option] = ruleSet.stringWhitelistExcludeOptions[option] + `|` + rule.regexString
							}
						}
					}
				} else {
					for option, allowed := range rule.options {
						if allowed {
							if ruleSet.stringBlacklistIncludeOptions[option] == `` {
								ruleSet.stringBlacklistIncludeOptions[option] = rule.regexString
							} else {
								ruleSet.stringBlacklistIncludeOptions[option] = ruleSet.stringBlacklistIncludeOptions[option] + `|` + rule.regexString
							}
						} else {
							if ruleSet.stringBlacklistExcludeOptions[option] == `` {
								ruleSet.stringBlacklistExcludeOptions[option] = rule.regexString
							} else {
								ruleSet.stringBlacklistExcludeOptions[option] = ruleSet.stringBlacklistExcludeOptions[option] + `|` + rule.regexString
							}

						}
					}
				}
			} else {
				if rule.isException {
					if ruleSet.stringBasicWhitelist == `` {
						ruleSet.stringBasicWhitelist = rule.regexString
					} else {
						ruleSet.stringBasicWhitelist = ruleSet.stringBasicWhitelist + `|` + rule.regexString
					}
				} else {
					if ruleSet.stringBasicBlacklist == `` {
						ruleSet.stringBasicBlacklist = rule.regexString
					} else {
						ruleSet.stringBasicBlacklist = ruleSet.stringBasicBlacklist + `|` + rule.regexString
					}
				}
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

	compileAllRegex(ruleSet)
	return ruleSet, nil
}

func compileAllRegex(ruleSet *RuleSet) {
	ruleSet.regexBasicWhitelist = regexp.MustCompile(ruleSet.stringBasicWhitelist)
	ruleSet.regexBasicBlacklist = regexp.MustCompile(ruleSet.stringBasicBlacklist)
	for option, _ := range ruleSet.stringWhitelistIncludeOptions {
		ruleSet.regexWhitelistIncludeOptions[option] = regexp.MustCompile(ruleSet.stringWhitelistIncludeOptions[option])
	}
	for option, _ := range ruleSet.stringWhitelistExcludeOptions {
		ruleSet.regexWhitelistExcludeOptions[option] = regexp.MustCompile(ruleSet.stringWhitelistExcludeOptions[option])
	}
	for option, _ := range ruleSet.stringBlacklistIncludeOptions {
		ruleSet.regexBlacklistIncludeOptions[option] = regexp.MustCompile(ruleSet.stringBlacklistIncludeOptions[option])
	}
	for option, _ := range ruleSet.stringBlacklistExcludeOptions {
		ruleSet.regexBlacklistExcludeOptions[option] = regexp.MustCompile(ruleSet.stringBlacklistExcludeOptions[option])
	}
	for domain, _ := range ruleSet.stringBlacklistIncludeDomains {
		ruleSet.regexBlacklistIncludeDomains[domain] = regexp.MustCompile(ruleSet.stringBlacklistIncludeDomains[domain])
	}
	for domain, _ := range ruleSet.stringBlacklistExcludeDomains {
		ruleSet.regexBlacklistExcludeDomains[domain] = regexp.MustCompile(ruleSet.stringBlacklistExcludeDomains[domain])
	}
}
func (rule *ruleAdBlock) OptionsKeys() []string {
	opts := []string{}
	for option := range rule.options {
		opts = append(opts, option)
	}

	if rule.domains != nil && len(rule.domains) > 0 {
		opts = append(opts, "domain")
	}

	return opts
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
