package adblockgoparser

import (
	"fmt"
	"testing"
)

func TestExample01(t *testing.T) {
	m := &Matcher{
		next: map[rune]*Matcher{},
	}
	rule1, _ := ParseRule("/banner/*/img^")
	rule2, _ := ParseRule("||ads.example.com^")
	rule3, _ := ParseRule("|http://example.com/|")
	m.add(rule1)
	m.add(rule2)
	m.add(rule3)

	fmt.Println("Final", m.Match(reqFromURL("http://example.com/banner/foo/img")))
	fmt.Println("Final", m.Match(reqFromURL("http://example.com/banner/foo/bar/img?param")))
	fmt.Println("Final", m.Match(reqFromURL("http://example.com/banner//img/foo")))
	fmt.Println("Final", m.Match(reqFromURL("http://example.com/banner/foo/img:8000")))
	fmt.Println("Final", m.Match(reqFromURL("http://example.com/banner/img")))
	fmt.Println("Final", m.Match(reqFromURL("http://example.com/banner/foo/imgraph")))
	fmt.Println("Final", m.Match(reqFromURL("http://example.com/banner/foo/img.gif")))

}

func TestExample02(t *testing.T) {
	rule1, _ := ParseRule("/assets/scripts/^")
	rule2, _ := ParseRule("/assets/$script")

	m := &Matcher{
		next: map[rune]*Matcher{},
	}
	m.add(rule1)
	m.add(rule2)
	fmt.Println(m)
	fmt.Println("Final", m.Match(reqFromURL("/assets/scripts/index.js")))

}
