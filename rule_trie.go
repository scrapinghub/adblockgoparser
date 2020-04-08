package adblockgoparser

import (
	"path/filepath"
	"strings"
)

type Matcher struct {
	next  map[rune]*Matcher
	rules []*ruleAdBlock
}

func (pathMatcher *Matcher) add(rule *ruleAdBlock) {
	var runes []rune
	switch rule.ruleType {
	case addressPart:
		runes = []rune(rule.ruleText)
	case domainName:
		runes = []rune(rule.ruleText[2 : len(rule.ruleText)-1])
	case exactAddress:
		runes = []rune(rule.ruleText[1 : len(rule.ruleText)-1])
	}
	pathMatcher.addPath(runes, rule)
}

func (pathMatcher *Matcher) addPath(runes []rune, rule *ruleAdBlock) {
	if len(runes) == 0 {

		pathMatcher.rules = append(pathMatcher.rules, rule)
		return
	}

	if string(runes[0]) == "^" {

		pathMatcher.rules = append(pathMatcher.rules, rule)
		return
	}

	if _, ok := pathMatcher.next[runes[0]]; !ok {

		pathMatcher.next[runes[0]] = &Matcher{
			next: map[rune]*Matcher{},
		}
	}

	pathMatcher.next[runes[0]].addPath(runes[1:], rule)
}

func (pathMatcher *Matcher) Match(req *Request) bool {
	path := req.URL.Path
	pathRunes := []rune(path)
	return pathMatcher.findNext(pathRunes, req)
}

func (pathMatcher *Matcher) findNext(runes []rune, req *Request) bool {
	match := false
	if len(pathMatcher.rules) != 0 {
		path := strings.ToLower(req.URL.Path)
		if strings.HasSuffix(path, ".gz") {
			path = path[:len(path)-len(".gz")]
		}
		for _, rule := range pathMatcher.rules {
			if len(rule.domains) > 0 {
				// hostname := strings.ToLower(req.URL.Hostname())
				// for domain, active := range rule.domains {
				// 	// validate domain
				// }
			}

			if rule.regex.MatchString(req.URL.String()) { // This line need to be removed and add simpler validation
				match = true
				for option, active := range rule.options {
					switch {
					case option == "xmlhttprequest":
					case option == "third-party":
					case option == "script":
						switch filepath.Ext(path) {
						case ".js":
							match = match && active
						}
					case option == "image":
						switch filepath.Ext(path) {
						case ".jpg", ".jpeg", ".png", ".gif", ".webp", ".tiff", ".psd", ".raw", ".bmp", ".heif", ".indd", ".jpeg2000":
							match = match && active
						}
					case option == "stylesheet":
						switch filepath.Ext(path) {
						case ".css":
							match = match && active
						}
					case option == "font":
						switch filepath.Ext(path) {
						case ".otf", ".ttf", ".fnt":
							match = match && active
						}
					}
				}
				if match {
					return true
				}
			}
		}
	}

	if len(runes) == 0 {
		return false
	}

	if _, ok := pathMatcher.next[runes[0]]; ok {
		match = pathMatcher.next[runes[0]].findNext(runes[1:], req)
	}

	if _, ok := pathMatcher.next['*']; ok && !match {
		for i := range runes {
			if pathMatcher.next['*'].findNext(runes[i:], req) {
				return true
			}
		}
		return false
	}

	return match
}
