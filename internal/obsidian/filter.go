package obsidian

import (
	"path/filepath"
	"strings"
)

// SyncFilter controls which .obsidian/ config files are synced.
// Each field maps to an Obsidian app sync setting toggle.
// Files outside .obsidian/ are always synced.
type SyncFilter struct {
	MainSettings       bool // app.json, types.json
	Appearance         bool // appearance.json
	ThemesAndSnippets  bool // themes/*, snippets/*.css
	Hotkeys            bool // hotkeys.json
	ActiveCorePlugins  bool // core-plugins.json, core-plugins-migration.json
	CorePluginSettings bool // other top-level .json files in .obsidian/
	CommunityPlugins   bool // community-plugins.json
	InstalledPlugins   bool // plugins/*/manifest.json, main.js, styles.css, data.json
}

// knownConfigFiles maps top-level .obsidian/ filenames to the toggle
// that controls them. Files not in this map fall under CorePluginSettings.
var knownConfigFiles = map[string]string{
	"app.json":                    "main",
	"types.json":                  "main",
	"appearance.json":             "appearance",
	"hotkeys.json":                "hotkeys",
	"core-plugins.json":           "core-plugins",
	"core-plugins-migration.json": "core-plugins",
	"community-plugins.json":      "community-plugins",
	"workspace.json":              "never",
	"workspace-mobile.json":       "never",
}

// AllowPath returns true if the given relative path should be synced
// according to the current filter settings. Paths outside .obsidian/
// are always allowed.
func (f *SyncFilter) AllowPath(relPath string) bool {
	relPath = normalizePath(relPath)

	// Non-.obsidian paths always sync.
	if !strings.HasPrefix(relPath, ".obsidian/") && relPath != ".obsidian" {
		return true
	}

	// The .obsidian directory itself: allow if any toggle is on.
	if relPath == ".obsidian" {
		return f.anyEnabled()
	}

	// Strip the .obsidian/ prefix to get the subpath.
	sub := strings.TrimPrefix(relPath, ".obsidian/")

	// themes/ directory
	if strings.HasPrefix(sub, "themes/") || sub == "themes" {
		return f.ThemesAndSnippets
	}

	// snippets/ directory
	if strings.HasPrefix(sub, "snippets/") || sub == "snippets" {
		return f.ThemesAndSnippets
	}

	// plugins/ directory (installed community plugins)
	if strings.HasPrefix(sub, "plugins/") || sub == "plugins" {
		return f.InstalledPlugins
	}

	// Top-level file in .obsidian/
	if !strings.Contains(sub, "/") {
		return f.allowConfigFile(sub)
	}

	// Anything else under .obsidian/ with subdirectories not matched
	// above: treat as core plugin settings.
	return f.CorePluginSettings
}

// allowConfigFile checks whether a top-level file in .obsidian/ is
// allowed based on the known file map and toggle state.
func (f *SyncFilter) allowConfigFile(filename string) bool {
	category, known := knownConfigFiles[filename]
	if !known {
		// Unknown top-level .json files are core plugin settings
		// (e.g. daily-notes.json, templates.json, graph.json).
		if filepath.Ext(filename) == ".json" {
			return f.CorePluginSettings
		}
		// Non-json files in .obsidian/ root: allow if any config sync is on.
		return f.CorePluginSettings
	}

	switch category {
	case "main":
		return f.MainSettings
	case "appearance":
		return f.Appearance
	case "hotkeys":
		return f.Hotkeys
	case "core-plugins":
		return f.ActiveCorePlugins
	case "community-plugins":
		return f.CommunityPlugins
	case "never":
		return false
	default:
		return false
	}
}

func (f *SyncFilter) anyEnabled() bool {
	return f.MainSettings ||
		f.Appearance ||
		f.ThemesAndSnippets ||
		f.Hotkeys ||
		f.ActiveCorePlugins ||
		f.CorePluginSettings ||
		f.CommunityPlugins ||
		f.InstalledPlugins
}
