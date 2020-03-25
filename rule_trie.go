package adblockgoparser

import (
	"fmt"
	"regexp"
	"strings"
)

type Trie struct {
	isRoot       bool
	isLeaf       bool
	part         string
	parent       *Trie
	children     []*Trie
	includeRules []string
	includeRegex *regexp.Regexp
	excludeRules []string
	excludeRegex *regexp.Regexp
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
		re, err := combinedStringRegex(trie.includeRules)
		if err != nil {
			return ErrCompilingRegex
		}
		trie.includeRegex = re

		re, err = combinedStringRegex(trie.excludeRules)
		if err != nil {
			return ErrCompilingRegex
		}
		trie.excludeRegex = re
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

func NewChild(parent *Trie, part string, isLeaf bool) *Trie {
	trie := &Trie{
		parent:   parent,
		part:     part,
		children: []*Trie{},
		isLeaf:   isLeaf,
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

func (parent *Trie) addChild(part string, isLeaf bool) *Trie {
	child, exists := parent.hasChild(part)
	if !exists {
		child = NewChild(parent, part, isLeaf)
		parent.children = append(parent.children, child)
	}
	return child
}

func (trie *Trie) include(regexString string) {
	trie.includeRules = append(trie.includeRules, regexString)
}

func (trie *Trie) exclude(regexString string) {
	trie.excludeRules = append(trie.excludeRules, regexString)
}
