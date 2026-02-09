package vault

import (
	"bytes"

	"gopkg.in/yaml.v3"
)

// Frontmatter holds parsed YAML frontmatter fields.
type Frontmatter struct {
	Tags []string `yaml:"tags"`
}

// parseFrontmatter extracts YAML frontmatter from markdown content.
// Returns nil if no frontmatter is found.
func parseFrontmatter(content []byte) *Frontmatter {
	if !bytes.HasPrefix(content, []byte("---")) {
		return nil
	}

	// Find the closing delimiter. It must be on its own line.
	rest := content[3:]
	// Skip the rest of the opening line (could be "---\n" or "---\r\n").
	idx := bytes.IndexByte(rest, '\n')
	if idx < 0 {
		return nil
	}
	rest = rest[idx+1:]

	end := bytes.Index(rest, []byte("\n---"))
	if end < 0 {
		return nil
	}

	block := rest[:end]

	var fm Frontmatter
	if err := yaml.Unmarshal(block, &fm); err != nil {
		return nil
	}
	return &fm
}
