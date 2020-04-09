package adblockgoparser

import (
	"path/filepath"
	"strings"
)

type Matcher struct {
	addressPartMatcher  *PathMatcher
	domainNameMatcher   *PathMatcher
	exactAddressMatcher *PathMatcher
	regexpRules         []*ruleAdBlock
}

type PathMatcher struct {
	next  map[rune]*PathMatcher
	rules []*ruleAdBlock
}

func (matcher *Matcher) add(rule *ruleAdBlock) {
	var runes []rune
	text := strings.ToLower(rule.ruleText)
	switch rule.ruleType {
	case addressPart:
		runes = []rune(text)
		matcher.addressPartMatcher.addPath(runes, rule)
	case domainName:
		runes = []rune(text[2 : len(text)-1])
		matcher.domainNameMatcher.addPath(runes, rule)
	case exactAddress:
		runes = []rune(text[1 : len(text)-1])
		matcher.exactAddressMatcher.addPath(runes, rule)
	case regexRule:
		matcher.regexpRules = append(matcher.regexpRules, rule)
	}
}

func (pathMatcher *PathMatcher) addPath(runes []rune, rule *ruleAdBlock) {
	if len(runes) == 0 || string(runes[0]) == "^" {
		pathMatcher.rules = append(pathMatcher.rules, rule)
		return
	}

	if _, ok := pathMatcher.next[runes[0]]; !ok {
		pathMatcher.next[runes[0]] = &PathMatcher{
			next: map[rune]*PathMatcher{},
		}
	}

	pathMatcher.next[runes[0]].addPath(runes[1:], rule)
}

func (matcher *Matcher) Match(req *Request) bool {
	// Match path
	pathRunes := []rune(strings.ToLower(req.URL.Path))
	for i := range pathRunes {
		if matcher.addressPartMatcher.findNext(pathRunes[i:], req) {
			return true
		}
	}

	// Match domain and subdomains
	hnRunes := []rune(strings.ToLower(req.URL.Hostname()))
	for i := range hnRunes {
		if matcher.domainNameMatcher.findNext(hnRunes[i:], req) {
			return true
		}
	}

	// Match exact address
	uriRunes := []rune(strings.ToLower(req.URL.String()))
	if matcher.exactAddressMatcher.findNext(uriRunes, req) {
		return true
	}

	// Match direct regexp
	uri := req.URL.String()
	for _, rule := range matcher.regexpRules {
		if rule.regex.MatchString(uri) {
			return true
		}
	}
	return false
}

func (pathMatcher *PathMatcher) findNext(runes []rune, req *Request) bool {
	match := false
	if len(pathMatcher.rules) != 0 {
		for _, rule := range pathMatcher.rules {
			if matchDomains(rule, req) && matchOptions(rule, req) && rule.regex.MatchString(req.URL.String()) { // This line need to be removed and add simpler validation
				return true
			}
		}
	}
	if len(runes) == 0 {
		return false
	}

	if _, ok := pathMatcher.next[runes[0]]; ok {
		match = pathMatcher.next[runes[0]].findNext(runes[1:], req)
		if match {
			return true
		}
	}

	if _, ok := pathMatcher.next['*']; ok && !match {
		for i := range runes {
			match := pathMatcher.next['*'].findNext(runes[i:], req)
			if match {
				return true
			}
		}
	}

	return false
}

func matchDomains(rule *ruleAdBlock, req *Request) bool {
	allowedDomain := true
	matchCase := false
	hostname := req.URL.Hostname()
	if _, matchCase = rule.options["match-case"]; !matchCase {
		hostname = strings.ToLower(hostname)
	}
	if rule.ruleType == domainName {
		if !strings.HasSuffix(hostname, rule.ruleText[2:len(rule.ruleText)-1]) {
			allowedDomain = false
		}
	}
	if len(rule.domains) > 0 {
		for domain, active := range rule.domains {
			if !matchCase {
				domain = strings.ToLower(domain)
			}
			if !(strings.HasSuffix(hostname, domain) == active) {
				allowedDomain = false
				break
			}
		}
	}
	return allowedDomain
}

func matchOptions(rule *ruleAdBlock, req *Request) bool {
	matchOption := true
	path := strings.ToLower(req.URL.Path)
	if strings.HasSuffix(path, ".gz") {
		path = path[:len(path)-len(".gz")]
	}

	if len(rule.options) > 0 {
		matchOption = false
		for option, active := range rule.options {
			switch {
			case option == "xmlhttprequest":
			case option == "third-party":
			case option == "match-case":
				matchOption = true
			case option == "script":
				switch filepath.Ext(path) {
				case ".js":
					return active
				default:
					return !active
				}
			case option == "image":
				switch filepath.Ext(path) {
				case ".jpg", ".jpeg", ".png", ".gif", ".webp", ".tiff", ".psd", ".raw", ".bmp", ".heif", ".indd", ".jpeg2000":
					return active
				default:
					return !active
				}
			case option == "stylesheet":
				switch filepath.Ext(path) {
				case ".css":
					return active
				default:
					return !active
				}
			case option == "font":
				switch filepath.Ext(path) {
				case ".otf", ".ttf", ".fnt":
					return active
				default:
					return !active
				}
			}
		}
	}
	return matchOption
}
