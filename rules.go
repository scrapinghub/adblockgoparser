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

type ruleAdBlock struct {
	regex       *regexp.Regexp
	options     map[string]bool
	isException bool
	domains     map[string]bool
	domainRule  bool
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

	if strings.Contains(ruleText, "##") || strings.Contains(ruleText, "#@#") || strings.Contains(ruleText, "#?#") {
		return nil, ErrSkipHTML
	}

	rule.isException = strings.HasPrefix(ruleText, "@@")
	if rule.isException {
		ruleText = ruleText[2:]
	}

	if strings.Contains(ruleText, "$") {
		parts := strings.SplitN(ruleText, "$", 2)
		ruleText = parts[0]

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

	if strings.HasPrefix(ruleText, "||") && strings.HasSuffix(ruleText, "^") {
		domain := ruleText
		domain = strings.TrimPrefix(domain, "||")
		domain = strings.TrimSuffix(domain, "^")
		rule.domains[domain] = true
		rule.domainRule = true
	}

	re, err := regexp.Compile(ruleToRegexp(ruleText))
	if err != nil {
		return nil, ErrCompilingRegex
	}
	rule.regex = re
	return rule, nil
}

type RuleSet struct {
	whitelistTrie *Trie
	blacklistTrie *Trie
}

func (ruleSet *RuleSet) Allow(req Request) bool {
	return ruleSet.whitelistTrie.Match(req) || !ruleSet.blacklistTrie.Match(req)
}

func NewRuleSetFromList(rulesStr []string) (*RuleSet, error) {
	ruleSet := &RuleSet{
		whitelistTrie: CreateRoot(),
		blacklistTrie: CreateRoot(),
	}
	rootWhitelistTrie := ruleSet.whitelistTrie
	rootBlacklistTrie := ruleSet.blacklistTrie
	// Start parsing
	for _, ruleStr := range rulesStr {
		rule, err := ParseRule(ruleStr)
		switch {
		case err == nil:
			// Blacklist without options nor domain filter
			if !rule.isException && len(rule.domains) == 0 && len(rule.options) == 0 {
				rootBlacklistTrie.include(rule.regex.String(), false, false)
				continue
			}
			// Whitelist without options nor domain filter
			if rule.isException && len(rule.domains) == 0 && len(rule.options) == 0 {
				rootWhitelistTrie.include(rule.regex.String(), false, false)
				continue
			}
			// Blacklist without options with domain filter
			if !rule.isException && len(rule.domains) > 0 && len(rule.options) == 0 {
				hasAllowed := false
				for domain, allowed := range rule.domains {
					node := rootBlacklistTrie
					parts := strings.Split(domain, ".")
					for i := len(parts) - 1; i >= 0; i-- {
						node = node.addChild(parts[i])
						isLeaf := i == 0
						if !isLeaf {
							continue
						}
						if allowed {
							hasAllowed = true
							node.include(rule.regex.String(), true, allowed)
						} else {
							node.exclude(rule.regex.String(), true, allowed)
						}
					}
				}
				if !hasAllowed {
					rootBlacklistTrie.exclude(rule.regex.String(), false, false)
				}
				continue
			}
			// Whitelist without options with domain filter
			if rule.isException && len(rule.domains) > 0 && len(rule.options) == 0 {
				hasAllowed := false
				for domain, allowed := range rule.domains {
					node := rootWhitelistTrie
					parts := strings.Split(domain, ".")
					for i := len(parts) - 1; i >= 0; i-- {
						node = node.addChild(parts[i])
						isLeaf := i == 0
						if !isLeaf {
							continue
						}
						if allowed {
							hasAllowed = true
							node.include(rule.regex.String(), true, allowed)
						} else {
							node.exclude(rule.regex.String(), true, allowed)
						}
					}
				}
				if !hasAllowed {
					rootWhitelistTrie.exclude(rule.regex.String(), false, false)
				}
				continue
			}
			// Blacklist with options with domain filter
			if !rule.isException && len(rule.domains) > 0 && len(rule.options) >= 0 {
				hasAllowed := false
				for domain, allowed := range rule.domains {
					node := rootBlacklistTrie
					parts := strings.Split(domain, ".")
					for i := len(parts) - 1; i >= 0; i-- {
						isLeaf := i == 0
						node = node.addChild(parts[i])
						if !isLeaf {
							continue
						}
						if allowed {
							hasAllowed = true
							addRegexpBasedOnOptions(node, rule, true, allowed)
						} else {
							addRegexpBasedOnOptions(node, rule, true, allowed)
						}
					}
				}
				if !hasAllowed {
					addRegexpBasedOnOptions(rootBlacklistTrie, rule, false, false)
				}
				continue
			}
			// Whitelist with options with domain filter
			if rule.isException && len(rule.domains) > 0 && len(rule.options) >= 0 {
				hasAllowed := false
				for domain, allowed := range rule.domains {
					node := rootWhitelistTrie
					parts := strings.Split(domain, ".")
					for i := len(parts) - 1; i >= 0; i-- {
						isLeaf := i == 0
						node = node.addChild(parts[i])
						if !isLeaf {
							continue
						}
						if allowed {
							hasAllowed = true
							addRegexpBasedOnOptions(node, rule, true, allowed)
						} else {
							addRegexpBasedOnOptions(node, rule, true, allowed)
						}
					}
				}
				if !hasAllowed {
					addRegexpBasedOnOptions(rootBlacklistTrie, rule, false, false)
				}
				continue
			}
			// Blacklist with options without domain filter
			if !rule.isException && len(rule.domains) == 0 && len(rule.options) > 0 {
				addRegexpBasedOnOptions(rootBlacklistTrie, rule, false, false)
				continue
			}
			// Whitelist with options without domain filter
			if rule.isException && len(rule.domains) == 0 && len(rule.options) > 0 {
				addRegexpBasedOnOptions(rootWhitelistTrie, rule, false, false)
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
	rootBlacklistTrie.compileAllLeafs()
	rootWhitelistTrie.compileAllLeafs()
	return ruleSet, nil
}

func addRegexpBasedOnOptions(node *Trie, rule *ruleAdBlock, hasDomain bool, domainActivated bool) {
	if rule.domainRule {
		for option, optionInclude := range rule.options {
			var regexpStr string
			switch option {
			case "xmlhttprequest":
			case "script":
				regexpStr = `(?:\.(?:js|js\.gz))$`
			case "image":
				regexpStr = `(?:\.(?:gif|jpe?g|png|webp|tiff|psd|raw|bmp|heif|indd|jpeg2000))$`
			case "stylesheet":
				regexpStr = `(?:\.css)$`
			case "font":
				regexpStr = `(?:\.(?:otf|ttf|fnt))$`
			case "third-party":
			}
			if optionInclude {
				node.include(regexpStr, hasDomain, domainActivated)
			} else {
				node.exclude(regexpStr, hasDomain, domainActivated)
			}
		}
	} else {
		for option, optionInclude := range rule.options {
			var regexpStr string
			switch option {
			case "xmlhttprequest":
			case "script":
				regexpStr = rule.regex.String() + `(?:\.(?:js|js\.gz))$`
			case "image":
				regexpStr = rule.regex.String() + `(?:\.(?:gif|jpe?g|png|webp|tiff|psd|raw|bmp|heif|indd|jpeg2000))$`
			case "stylesheet":
				regexpStr = rule.regex.String() + `(?:\.css)$`
			case "font":
				regexpStr = rule.regex.String() + `(?:\.(?:otf|ttf|fnt))$`
			case "third-party":
			}
			if optionInclude {
				node.include(regexpStr, hasDomain, domainActivated)
			} else {
				node.exclude(regexpStr, hasDomain, domainActivated)
			}
		}
	}
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
