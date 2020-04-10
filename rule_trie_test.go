package adblockgoparser

// func TestExample01(t *testing.T) {
// 	m := &matcher{
// 		addressPartMatcher: &pathMatcher{
// 			next: map[rune]*pathMatcher{},
// 		},
// 	}
// 	rule1, _ := ParseRule("/banner/*/img^")
// 	rule2, _ := ParseRule("||ads.example.com^")
// 	rule3, _ := ParseRule("|http://example.com/|")
// 	m.add(rule1)
// 	m.add(rule2)
// 	m.add(rule3)

// 	fmt.Println("Final", m.Match(reqFromURL("http://example.com/banner/foo/img")))
// 	fmt.Println("Final", m.Match(reqFromURL("http://example.com/banner/foo/bar/img?param")))
// 	fmt.Println("Final", m.Match(reqFromURL("http://example.com/banner//img/foo")))
// 	fmt.Println("Final", m.Match(reqFromURL("http://example.com/banner/foo/img:8000")))
// 	fmt.Println("Final", m.Match(reqFromURL("http://example.com/banner/img")))
// 	fmt.Println("Final", m.Match(reqFromURL("http://example.com/banner/foo/imgraph")))
// 	fmt.Println("Final", m.Match(reqFromURL("http://example.com/banner/foo/img.gif")))

// }

// func TestExample02(t *testing.T) {
// 	rule1, _ := ParseRule("/assets/scripts/^")
// 	rule2, _ := ParseRule("/assets/$script")

// 	m := &matcher{
// 		addressPartMatcher: &pathMatcher{
// 			next: map[rune]*pathMatcher{},
// 		},
// 	}
// 	m.add(rule1)
// 	m.add(rule2)
// 	fmt.Println(m)
// 	fmt.Println("Final", m.Match(reqFromURL("/assets/scripts/index.js")))

// }
