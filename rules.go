package adblockgoparser

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
)

var (
	ErrSkipComment     = errors.New("Commented rules are skipped")
	ErrSkipHTML        = errors.New("HTML rules are skipped")
	ErrEmptyLine       = errors.New("Empty lines are skipped")
	ErrUnsupportedRule = errors.New("Unsupported option rules are skipped")
	ErrCompilingRegex  = errors.New("Error compiling regexp")
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
	// Except domain
	supportedOptions = []string{
		"image",
		"script",
		"stylesheet",
		"font",
		"thirdparty",
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

type ruleAdBlock struct {
	regex       *regexp.Regexp
	options     map[string]bool
	isException bool
	domains     map[string]bool
}

func ParseRule(ruleText string) (*ruleAdBlock, error) {
	ruleText = strings.TrimSpace(ruleText)
	if ruleText == "" {
		return nil, ErrEmptyLine
	}
	rule := &ruleAdBlock{
		domains: map[string]bool{},
		options: map[string]bool{},
	}

	if strings.HasPrefix(ruleText, "!") || strings.HasPrefix(ruleText, "[Adblock") {
		return nil, ErrSkipComment
	}

	if strings.Contains(ruleText, "##") || strings.Contains(ruleText, "#@#") {
		return nil, ErrSkipHTML
	}

	rule.isException = strings.HasPrefix(ruleText, "@@")
	if rule.isException {
		ruleText = ruleText[2:]
	}

	if strings.Contains(ruleText, "$") {
		parts := strings.SplitN(ruleText, "$", 2)
		length := len(parts)

		if length > 0 {
			ruleText = parts[0]
		}

		if length > 1 {
			for _, option := range strings.Split(parts[1], ",") {
				if strings.HasPrefix(option, "domain=") {
					rule.domains = parseDomainOption(option)
				} else {
					optionName := strings.TrimPrefix(option, "~")
					if _, ok := supportedOptionsPat[optionName]; !ok {
						return nil, ErrUnsupportedRule
					}
					rule.options[optionName] = !strings.HasPrefix(option, "~")
				}
			}
		}
	}

	re, err := regexp.Compile(ruleToRegexp(ruleText))
	if err != nil {
		return nil, ErrCompilingRegex
	}
	rule.regex = re
	return rule, nil
}

type RuleSet struct {
	// whitelist      []*ruleAdBlock
	// whitelistRegex *regexp.Regexp
	// blacklist      []*ruleAdBlock
	// blacklistRegex *regexp.Regexp

	whitelistTrie *Trie
	blacklistTrie *Trie

	// whitelistDomainsNoOptions   []*ruleAdBlock
	whitelistDomainsWithOptions []*ruleAdBlock
	// blacklistDomainsNoOptions   []*ruleAdBlock
	blacklistDomainsWithOptions []*ruleAdBlock

	whitelistIncludeOptions map[string][]*ruleAdBlock
	whitelistExcludeOptions map[string][]*ruleAdBlock
	blacklistIncludeOptions map[string][]*ruleAdBlock
	blacklistExcludeOptions map[string][]*ruleAdBlock
}

func matchWhite(ruleSet RuleSet, req Request) bool {
	node := ruleSet.whitelistTrie
	if node.includeRegex != nil && node.includeRegex.MatchString(req.URL.String()) {
		return true
	}

	domain := req.URL.Hostname()
	parts := strings.Split(domain, ".")

	exists := false
	block := false
	for i := len(parts) - 1; i >= 0 && node != nil; i-- {
		node, exists = node.hasChild(parts[i])
		if exists {
			include := node.includeRegex != nil && node.includeRegex.MatchString(req.URL.String())
			exclude := node.excludeRegex != nil && !node.excludeRegex.MatchString(req.URL.String())
			block = include && !exclude
		}
	}
	return block
}

func matchBlack(ruleSet RuleSet, req Request) bool {
	node := ruleSet.blacklistTrie
	if node.includeRegex != nil && node.includeRegex.MatchString(req.URL.String()) {
		return true
	}

	domain := req.URL.Hostname()
	parts := strings.Split(domain, ".")

	exists := false
	block := false
	for i := len(parts) - 1; i >= 0 && node != nil; i-- {
		node, exists = node.hasChild(parts[i])
		if exists {
			include := node.includeRegex != nil && node.includeRegex.MatchString(req.URL.String())
			exclude := node.excludeRegex != nil && !node.excludeRegex.MatchString(req.URL.String())
			block = include && !exclude
		}
	}
	return block
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
	var err error
	for option, _ := range include {
		includeRegex[option], err = combinedRegex(include[option])
		if err != nil {
			// ErrCompilingRegex
		}

	}
	for option, _ := range exclude {
		excludeRegex[option], err = combinedRegex(exclude[option])
		if err != nil {
			// ErrCompilingRegex
		}

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

func NewRuleSetFromStr(rulesStr []string) (*RuleSet, error) {
	ruleSet := &RuleSet{
		whitelistTrie:           CreateRoot(),
		blacklistTrie:           CreateRoot(),
		whitelistIncludeOptions: map[string][]*ruleAdBlock{},
		whitelistExcludeOptions: map[string][]*ruleAdBlock{},
		blacklistIncludeOptions: map[string][]*ruleAdBlock{},
		blacklistExcludeOptions: map[string][]*ruleAdBlock{},
	}
	// fmt.Println("Rotao", ruleSet.blacklistTrie.String())
	// Start parsing
	for _, ruleStr := range rulesStr {
		rule, err := ParseRule(ruleStr)
		switch {
		case err == nil:
			// Blacklist without options nor domain filter
			if !rule.isException && len(rule.domains) == 0 && len(rule.options) == 0 {
				ruleSet.blacklistTrie.include(rule.regex.String())
				continue
			}
			// Whitelist without options nor domain filter
			if rule.isException && len(rule.domains) == 0 && len(rule.options) == 0 {
				ruleSet.whitelistTrie.include(rule.regex.String())
				continue
			}
			// Blacklist without options with domain filter
			if !rule.isException && len(rule.domains) > 0 && len(rule.options) == 0 {
				for domain, allowed := range rule.domains {
					node := ruleSet.blacklistTrie
					parts := strings.Split(domain, ".")
					for i := len(parts) - 1; i >= 0; i-- {
						node = node.addChild(parts[i], i == 0)
						if allowed {
							node.include(rule.regex.String())
						} else {
							node.exclude(rule.regex.String())
						}
					}
				}
				continue
			}
			// Whitelist without options with domain filter
			if rule.isException && len(rule.domains) > 0 && len(rule.options) == 0 {
				for domain, allowed := range rule.domains {
					node := ruleSet.whitelistTrie
					parts := strings.Split(domain, ".")
					for i := len(parts) - 1; i >= 0; i-- {
						node = node.addChild(parts[i], i == 0)
						if allowed {
							node.include(rule.regex.String())
						} else {
							node.exclude(rule.regex.String())
						}
					}
				}
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
			errors.Is(err, ErrUnsupportedRule),
			errors.Is(err, ErrEmptyLine):
			return nil, fmt.Errorf("%w: %s", err, ruleStr)
		default:
			return nil, fmt.Errorf("Cannot parse rule: %w", err)
		}
	}
	ruleSet.blacklistTrie.compileAllLeafs()
	return ruleSet, nil
}

func combinedRegex(rules []*ruleAdBlock) (*regexp.Regexp, error) {
	var b strings.Builder
	for n, rule := range rules {
		if n == 0 {
			fmt.Fprintf(&b, "%s", rule.regex.String())
			continue
		}
		fmt.Fprintf(&b, "|%s", rule.regex.String())
	}
	if b.String() == "" {
		return nil, nil
	}

	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, ErrCompilingRegex
	}
	return re, nil

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
