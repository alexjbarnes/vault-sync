package vault

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseFrontmatter_WithTags(t *testing.T) {
	content := []byte("---\ntags:\n  - project\n  - go\n---\n# Hello")
	fm := parseFrontmatter(content)
	assert.NotNil(t, fm)
	assert.Equal(t, []string{"project", "go"}, fm.Tags)
}

func TestParseFrontmatter_InlineTags(t *testing.T) {
	content := []byte("---\ntags: [daily, journal]\n---\n# Today")
	fm := parseFrontmatter(content)
	assert.NotNil(t, fm)
	assert.Equal(t, []string{"daily", "journal"}, fm.Tags)
}

func TestParseFrontmatter_NoFrontmatter(t *testing.T) {
	content := []byte("# Just a heading\nSome text")
	fm := parseFrontmatter(content)
	assert.Nil(t, fm)
}

func TestParseFrontmatter_EmptyFrontmatter(t *testing.T) {
	// Empty block between delimiters: "---\n\n---" has a blank line.
	content := []byte("---\n\n---\n# Heading")
	fm := parseFrontmatter(content)
	assert.NotNil(t, fm)
	assert.Nil(t, fm.Tags)
}

func TestParseFrontmatter_NoClosingDelimiter(t *testing.T) {
	content := []byte("---\ntags: [a]\nNo closing")
	fm := parseFrontmatter(content)
	assert.Nil(t, fm)
}

func TestParseFrontmatter_EmptyContent(t *testing.T) {
	fm := parseFrontmatter([]byte(""))
	assert.Nil(t, fm)
}

func TestParseFrontmatter_OnlyDelimiters(t *testing.T) {
	content := []byte("---\ntitle: Hello\n---")
	fm := parseFrontmatter(content)
	assert.NotNil(t, fm)
}

func TestParseFrontmatter_InvalidYAML(t *testing.T) {
	content := []byte("---\n: invalid: yaml: [[\n---\n")
	fm := parseFrontmatter(content)
	assert.Nil(t, fm)
}

func TestParseFrontmatter_WindowsLineEndings(t *testing.T) {
	content := []byte("---\r\ntags:\r\n  - test\r\n---\r\n# Hello")
	fm := parseFrontmatter(content)
	assert.NotNil(t, fm)
	assert.Equal(t, []string{"test"}, fm.Tags)
}

func TestParseFrontmatter_NoNewlineAfterOpening(t *testing.T) {
	content := []byte("---")
	fm := parseFrontmatter(content)
	assert.Nil(t, fm)
}
