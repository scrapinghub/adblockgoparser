package adblockgoparser

import (
	"fmt"
	"regexp"
	"strings"
)

type Trie struct {
	isRoot                        bool
	isLeaf                        bool
	part                          string
	parent                        *Trie
	children                      []*Trie
	noDomainIncludeRules          []string
	noDomainExcludeRules          []string
	domainActivatedIncludeRules   []string
	domainActivatedExcludeRules   []string
	domainDeactivatedIncludeRules []string
	domainDeactivatedExcludeRules []string
	noDomainIncludeRegex          *regexp.Regexp
	noDomainExcludeRegex          *regexp.Regexp
	domainActivatedIncludeRegex   *regexp.Regexp
	domainActivatedExcludeRegex   *regexp.Regexp
	domainDeactivatedIncludeRegex *regexp.Regexp
	domainDeactivatedExcludeRegex *regexp.Regexp
}

func (trie *Trie) String() string {
	if trie.parent != nil && !trie.parent.isRoot {
		return fmt.Sprintf("%s.%s", trie.part, trie.parent)
	}
	if trie.part == "" {
		return fmt.Sprintf("Root")
	}
	return fmt.Sprintf("%s", trie.part)
}

func (root *Trie) Match(req Request) bool {
	node := root
	specificBlock := false
	generalBlock := false
	exists := false
	matched := false
	dInclude := false
	dExclude := false
	domain := req.URL.Hostname()
	parts := strings.Split(domain, ".")
	for i := len(parts) - 1; i >= 0; i-- {
		node, exists = node.hasChild(parts[i])
		if !exists {
			break
		}
		if node.isLeaf {
			aInclude := node.domainActivatedIncludeRegex != nil && node.domainActivatedIncludeRegex.MatchString(req.URL.String())
			aExclude := node.domainActivatedExcludeRegex != nil && !node.domainActivatedExcludeRegex.MatchString(req.URL.String())
			dInclude = node.domainDeactivatedIncludeRegex != nil && node.domainDeactivatedIncludeRegex.MatchString(req.URL.String())
			dExclude = node.domainDeactivatedExcludeRegex != nil && !node.domainDeactivatedExcludeRegex.MatchString(req.URL.String())
			matched = aInclude || aExclude || dInclude || dExclude
			specificBlock = aInclude || aExclude
		}
	}

	if matched {
		return specificBlock
	}

	node = root
	nInclude := node.noDomainIncludeRegex != nil && node.noDomainIncludeRegex.MatchString(req.URL.String())
	nExclude := node.noDomainExcludeRegex != nil && !node.noDomainExcludeRegex.MatchString(req.URL.String())
	generalBlock = nInclude || nExclude
	return generalBlock
}

func combinedStringRegex(regexStringList []string) (*regexp.Regexp, error) {
	var sb strings.Builder
	for n, str := range regexStringList {
		if n == 0 {
			fmt.Fprintf(&sb, "%s", str)
			continue
		}
		fmt.Fprintf(&sb, "|%s", str)
	}
	if sb.String() == "" {
		return nil, nil
	}

	re, err := regexp.Compile(sb.String())
	if err != nil {
		return nil, ErrCompilingRegex
	}
	return re, nil
}

func (trie *Trie) compileRegex() error {
	if trie.isLeaf {
		re, err := combinedStringRegex(trie.noDomainIncludeRules)
		if err != nil {
			return ErrCompilingRegex
		}
		trie.noDomainIncludeRegex = re

		re, err = combinedStringRegex(trie.noDomainExcludeRules)
		if err != nil {
			return ErrCompilingRegex
		}
		trie.noDomainExcludeRegex = re

		re, err = combinedStringRegex(trie.domainActivatedIncludeRules)
		if err != nil {
			return ErrCompilingRegex
		}
		trie.domainActivatedIncludeRegex = re

		re, err = combinedStringRegex(trie.domainActivatedExcludeRules)
		if err != nil {
			return ErrCompilingRegex
		}
		trie.domainActivatedExcludeRegex = re

		re, err = combinedStringRegex(trie.domainDeactivatedIncludeRules)
		if err != nil {
			return ErrCompilingRegex
		}
		trie.domainDeactivatedIncludeRegex = re

		re, err = combinedStringRegex(trie.domainDeactivatedExcludeRules)
		if err != nil {
			return ErrCompilingRegex
		}
		trie.domainDeactivatedExcludeRegex = re
	}
	return nil
}

func (trie *Trie) compileAllLeafs() error {
	err := trie.compileRegex()
	if err != nil {
		return ErrCompilingRegex
	}

	for _, child := range trie.children {
		err = child.compileAllLeafs()
		if err != nil {
			return ErrCompilingRegex
		}
	}

	return nil
}

func CreateRoot() *Trie {
	trie := &Trie{
		parent:   nil,
		isRoot:   true,
		isLeaf:   true,
		children: []*Trie{},
	}
	return trie
}

func NewChild(parent *Trie, part string) *Trie {
	trie := &Trie{
		parent:   parent,
		part:     part,
		children: []*Trie{},
	}
	return trie
}

func (trie *Trie) hasChild(part string) (*Trie, bool) {
	for _, child := range trie.children {
		if child.part == part {
			return child, true
		}
	}
	return nil, false
}

func (parent *Trie) addChild(part string) *Trie {
	child, exists := parent.hasChild(part)
	if !exists {
		child = NewChild(parent, part)
		parent.children = append(parent.children, child)
	}
	return child
}

func (trie *Trie) include(regexString string, hasDomain bool, domainActivated bool) {
	trie.isLeaf = true
	if !hasDomain {
		trie.noDomainIncludeRules = append(trie.noDomainIncludeRules, regexString)
		return
	}
	if domainActivated {
		trie.domainActivatedIncludeRules = append(trie.domainActivatedIncludeRules, regexString)
		return
	}
	trie.domainDeactivatedIncludeRules = append(trie.domainDeactivatedIncludeRules, regexString)
}

func (trie *Trie) exclude(regexString string, hasDomain bool, domainActivated bool) {
	trie.isLeaf = true
	if !hasDomain {
		trie.noDomainExcludeRules = append(trie.noDomainExcludeRules, regexString)
		return
	}
	if domainActivated {
		trie.domainActivatedExcludeRules = append(trie.domainActivatedExcludeRules, regexString)
		return
	}
	trie.domainDeactivatedExcludeRules = append(trie.domainDeactivatedExcludeRules, regexString)
}
