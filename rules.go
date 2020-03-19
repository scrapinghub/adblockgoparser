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
					if ok := strings.Contains(supportedOptionsPat, option); !ok {
						logger.Info(ErrUnsupportedRule, ": ", strings.TrimSpace(option))
						return nil, ErrUnsupportedRule
					}
					rule.options[strings.TrimPrefix(option, "~")] = !strings.HasPrefix(option, "~")
				}
			}
		}
	}

	rule.regexString = ruleToRegexp(rule.ruleText)

	return rule, nil
}

type RuleSet struct {
	regexBasicString            string
	regexBasicWhitelistString   string
	regexBasic                  *regexp.Regexp
	regexBasicWhitelist         *regexp.Regexp
	rulesOptionsString          map[string]string
	rulesOptionsWhitelistString map[string]string
	rulesOptionsRegex           map[string]*regexp.Regexp
	rulesOptionsWhitelistRegex  map[string]*regexp.Regexp
}

func matchWhite(ruleSet RuleSet, req Request) bool {
	didMatch := false
	if ruleSet.regexBasicWhitelistString != `` {
		didMatch = ruleSet.regexBasicWhitelist.MatchString(req.URL.String())
	}
	if didMatch {
		return true
	}

	options := extractOptionsFromRequest(req)
	for option, active := range options {
		if active && ruleSet.rulesOptionsWhitelistString[option] != `` {
			didMatch = ruleSet.rulesOptionsWhitelistRegex[option].MatchString(req.URL.String())
			if didMatch {
				return true
			}
		}
	}
	return false
}

func matchBlack(ruleSet RuleSet, req Request) bool {
	didMatch := false
	if ruleSet.regexBasicString != `` {
		didMatch = ruleSet.regexBasic.MatchString(req.URL.String())
	}
	if didMatch {
		return true
	}

	options := extractOptionsFromRequest(req)
	for option, active := range options {
		if active && ruleSet.rulesOptionsString[option] != `` {
			didMatch = ruleSet.rulesOptionsRegex[option].MatchString(req.URL.String())
			if didMatch {
				return true
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
		rulesOptionsString:          make(map[string]string, len(supportedOptions)),
		rulesOptionsWhitelistString: make(map[string]string, len(supportedOptions)),
		rulesOptionsRegex:           make(map[string]*regexp.Regexp, len(supportedOptions)),
		rulesOptionsWhitelistRegex:  make(map[string]*regexp.Regexp, len(supportedOptions)),
	}

	// Start parsing
	for _, ruleStr := range rulesStr {
		rule, err := parseRule(ruleStr)

		switch {
		case err == nil:
			if rule.options != nil && len(rule.options) > 0 {
				if rule.isException {
					for option := range rule.options {
						if ruleSet.rulesOptionsWhitelistString[option] == `` {
							ruleSet.rulesOptionsWhitelistString[option] = rule.regexString
						} else {
							ruleSet.rulesOptionsWhitelistString[option] = ruleSet.rulesOptionsWhitelistString[option] + `|` + rule.regexString
						}
					}
				} else {
					for option := range rule.options {
						if ruleSet.rulesOptionsString[option] == `` {
							ruleSet.rulesOptionsString[option] = rule.regexString
						} else {
							ruleSet.rulesOptionsString[option] = ruleSet.rulesOptionsString[option] + `|` + rule.regexString
						}
					}
				}
			} else {
				if rule.isException {
					if ruleSet.regexBasicWhitelistString == `` {
						ruleSet.regexBasicWhitelistString = rule.regexString
					} else {
						ruleSet.regexBasicWhitelistString = ruleSet.regexBasicWhitelistString + `|` + rule.regexString
					}
				} else {
					if ruleSet.regexBasicString == `` {
						ruleSet.regexBasicString = rule.regexString
					} else {
						ruleSet.regexBasicString = ruleSet.regexBasicString + `|` + rule.regexString
					}
				}
			}
		case errors.Is(err, ErrSkipComment),
			errors.Is(err, ErrSkipHTML),
			errors.Is(err, ErrUnsupportedRule),
			errors.Is(err, ErrEmptyLine):
			logger.Info(err, ": ", strings.TrimSpace(ruleStr))
		default:
			logger.Info("cannot parse rule: ", err)
			return nil, fmt.Errorf("cannot parse rule: %w", err)
		}
	}

	ruleSet.regexBasic = regexp.MustCompile(ruleSet.regexBasicString)
	ruleSet.regexBasicWhitelist = regexp.MustCompile(ruleSet.regexBasicWhitelistString)
	for option, _ := range ruleSet.rulesOptionsString {
		ruleSet.rulesOptionsRegex[option] = regexp.MustCompile(ruleSet.rulesOptionsString[option])
		ruleSet.rulesOptionsWhitelistRegex[option] = regexp.MustCompile(ruleSet.rulesOptionsWhitelistString[option])
	}
	return ruleSet, nil
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
