package adblockgoparser

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTrie(t *testing.T) {
	// root := CreateRoot()
	// fmt.Println(root)
	// child := root.addChild("com")
	// child = child.addChild("example")
	// child = child.addChild("bar")
	// child = child.addChild("any")
	// child := NewChild(root, "com")
	// root.children = append(root.children, child)
	// fmt.Println(root)
	// fmt.Println(child)
	// fmt.Println(child.parent)

	rules := []string{"/banner/*/img$domain=example.com|~bar.example.com"}
	ruleSet, err := NewRuleSetFromStr(rules)
	assert.NoError(t, err)
	// Block for `example.com` domain and its subdomain
	assert.False(t, ruleSet.Allow(reqFromURL("http://example.com/banner/foo/img")))
	assert.False(t, ruleSet.Allow(reqFromURL("http://anysubdomain.example.com/banner/foo/img")))
	// // But not for `bar` subdomain and its subdomain or other domain
	assert.True(t, ruleSet.Allow(reqFromURL("http://bar.example.com/banner/foo/img")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://foo.bar.example.com/banner/foo/img")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://example.net/banner/foo/img")))
	assert.True(t, ruleSet.Allow(reqFromURL("http://anysubdomain.example.net/banner/foo/img")))
}
