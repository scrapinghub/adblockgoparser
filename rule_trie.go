package adblockgoparser

import (
	"path/filepath"
	"strings"
)

type matcher struct {
	addressPartMatcher  *pathMatcher
	domainNameMatcher   *pathMatcher
	exactAddressMatcher *pathMatcher
	regexpRules         []*ruleAdBlock
}

type pathMatcher struct {
	next  map[rune]*pathMatcher
	rules []*ruleAdBlock
}

// Add Rule in a structured way to be able to match with Request
func (m *matcher) Add(rule *ruleAdBlock) {
	var runes []rune
	text := strings.ToLower(rule.ruleText)
	switch rule.ruleType {
	case addressPart:
		runes = []rune(text)
		m.addressPartMatcher.addPath(runes, rule)
	case domainName:
		runes = []rune(text[2 : len(text)-1])
		m.domainNameMatcher.addPath(runes, rule)
	case exactAddress:
		runes = []rune(text[1 : len(text)-1])
		m.exactAddressMatcher.addPath(runes, rule)
	case regexRule:
		m.regexpRules = append(m.regexpRules, rule)
	}
}

func (pm *pathMatcher) addPath(runes []rune, rule *ruleAdBlock) {
	// Append rule when getting to the end or find the address end signal
	if len(runes) == 0 || string(runes[0]) == "^" {
		pm.rules = append(pm.rules, rule)
		return
	}

	// If the next rune doesn't exist
	if _, ok := pm.next[runes[0]]; !ok {
		// Create the next rune
		pm.next[runes[0]] = &pathMatcher{
			next: map[rune]*pathMatcher{},
		}
	}

	// Add the next rune, removing the current
	pm.next[runes[0]].addPath(runes[1:], rule)
}

// Match the Request against all rules
func (m *matcher) Match(req *Request) bool {
	// Match path
	pathRunes := []rune(strings.ToLower(req.URL.Path))
	for i := range pathRunes {
		if m.addressPartMatcher.findNext(pathRunes[i:], req) {
			return true
		}
	}

	// Match domain and subdomains
	hnRunes := []rune(strings.ToLower(req.URL.Hostname()))
	for i := range hnRunes {
		if m.domainNameMatcher.findNext(hnRunes[i:], req) {
			return true
		}
	}

	// Match exact address
	URLRunes := []rune(strings.ToLower(req.URL.String()))
	if m.exactAddressMatcher.findNext(URLRunes, req) {
		return true
	}

	// Match direct regexp
	URL := req.URL.String()
	for _, rule := range m.regexpRules {
		if rule.regex.MatchString(URL) {
			return true
		}
	}
	return false
}

func (pm *pathMatcher) findNext(runes []rune, req *Request) bool {
	match := false
	// If find some rules in the current rune, try to match
	if len(pm.rules) != 0 {
		for _, rule := range pm.rules {
			if matchDomains(rule, req) && matchOptions(rule, req) && rule.regex.MatchString(req.URL.String()) { // This line need to be removed and add simpler validation
				return true
			}
		}
	}

	// If still have runes to looking for
	if len(runes) != 0 {
		// Go to the next expected rune
		if _, ok := pm.next[runes[0]]; ok {
			match = pm.next[runes[0]].findNext(runes[1:], req)
			if match {
				return true
			}
		}
	}

	// If the current path match has a wildcard
	if _, ok := pm.next['*']; ok && !match {
		// Start ignoring characters from URL
		for i := range runes {
			match := pm.next['*'].findNext(runes[i:], req)
			if match {
				return true
			}
		}
	}

	// Return false if no rules match neither has a path to follow nor wildcard
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
