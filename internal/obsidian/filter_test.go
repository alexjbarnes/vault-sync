package obsidian

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func allEnabled() *SyncFilter {
	return &SyncFilter{
		MainSettings:       true,
		Appearance:         true,
		ThemesAndSnippets:  true,
		Hotkeys:            true,
		ActiveCorePlugins:  true,
		CorePluginSettings: true,
		CommunityPlugins:   true,
		InstalledPlugins:   true,
	}
}

func allDisabled() *SyncFilter {
	return &SyncFilter{}
}

func TestAllowPath_NonObsidianAlwaysAllowed(t *testing.T) {
	f := allDisabled()
	assert.True(t, f.AllowPath("notes/hello.md"))
	assert.True(t, f.AllowPath("folder/sub/file.txt"))
	assert.True(t, f.AllowPath("README.md"))
}

func TestAllowPath_ObsidianDirRequiresAnyToggle(t *testing.T) {
	f := allDisabled()
	assert.False(t, f.AllowPath(".obsidian"))

	f.MainSettings = true
	assert.True(t, f.AllowPath(".obsidian"))
}

func TestAllowPath_MainSettings(t *testing.T) {
	f := allDisabled()
	assert.False(t, f.AllowPath(".obsidian/app.json"))
	assert.False(t, f.AllowPath(".obsidian/types.json"))

	f.MainSettings = true
	assert.True(t, f.AllowPath(".obsidian/app.json"))
	assert.True(t, f.AllowPath(".obsidian/types.json"))
}

func TestAllowPath_Appearance(t *testing.T) {
	f := allDisabled()
	assert.False(t, f.AllowPath(".obsidian/appearance.json"))

	f.Appearance = true
	assert.True(t, f.AllowPath(".obsidian/appearance.json"))
}

func TestAllowPath_ThemesAndSnippets(t *testing.T) {
	f := allDisabled()
	assert.False(t, f.AllowPath(".obsidian/themes"))
	assert.False(t, f.AllowPath(".obsidian/themes/minimal/theme.css"))
	assert.False(t, f.AllowPath(".obsidian/themes/minimal/manifest.json"))
	assert.False(t, f.AllowPath(".obsidian/snippets"))
	assert.False(t, f.AllowPath(".obsidian/snippets/custom.css"))

	f.ThemesAndSnippets = true
	assert.True(t, f.AllowPath(".obsidian/themes"))
	assert.True(t, f.AllowPath(".obsidian/themes/minimal/theme.css"))
	assert.True(t, f.AllowPath(".obsidian/themes/minimal/manifest.json"))
	assert.True(t, f.AllowPath(".obsidian/snippets"))
	assert.True(t, f.AllowPath(".obsidian/snippets/custom.css"))
}

func TestAllowPath_Hotkeys(t *testing.T) {
	f := allDisabled()
	assert.False(t, f.AllowPath(".obsidian/hotkeys.json"))

	f.Hotkeys = true
	assert.True(t, f.AllowPath(".obsidian/hotkeys.json"))
}

func TestAllowPath_ActiveCorePlugins(t *testing.T) {
	f := allDisabled()
	assert.False(t, f.AllowPath(".obsidian/core-plugins.json"))
	assert.False(t, f.AllowPath(".obsidian/core-plugins-migration.json"))

	f.ActiveCorePlugins = true
	assert.True(t, f.AllowPath(".obsidian/core-plugins.json"))
	assert.True(t, f.AllowPath(".obsidian/core-plugins-migration.json"))
}

func TestAllowPath_CorePluginSettings(t *testing.T) {
	f := allDisabled()
	// Unknown .json files in .obsidian/ root are core plugin settings.
	assert.False(t, f.AllowPath(".obsidian/daily-notes.json"))
	assert.False(t, f.AllowPath(".obsidian/templates.json"))
	assert.False(t, f.AllowPath(".obsidian/graph.json"))

	f.CorePluginSettings = true
	assert.True(t, f.AllowPath(".obsidian/daily-notes.json"))
	assert.True(t, f.AllowPath(".obsidian/templates.json"))
	assert.True(t, f.AllowPath(".obsidian/graph.json"))
}

func TestAllowPath_CommunityPlugins(t *testing.T) {
	f := allDisabled()
	assert.False(t, f.AllowPath(".obsidian/community-plugins.json"))

	f.CommunityPlugins = true
	assert.True(t, f.AllowPath(".obsidian/community-plugins.json"))
}

func TestAllowPath_InstalledPlugins(t *testing.T) {
	f := allDisabled()
	assert.False(t, f.AllowPath(".obsidian/plugins"))
	assert.False(t, f.AllowPath(".obsidian/plugins/dataview/manifest.json"))
	assert.False(t, f.AllowPath(".obsidian/plugins/dataview/main.js"))
	assert.False(t, f.AllowPath(".obsidian/plugins/dataview/styles.css"))
	assert.False(t, f.AllowPath(".obsidian/plugins/dataview/data.json"))

	f.InstalledPlugins = true
	assert.True(t, f.AllowPath(".obsidian/plugins"))
	assert.True(t, f.AllowPath(".obsidian/plugins/dataview/manifest.json"))
	assert.True(t, f.AllowPath(".obsidian/plugins/dataview/main.js"))
	assert.True(t, f.AllowPath(".obsidian/plugins/dataview/styles.css"))
	assert.True(t, f.AllowPath(".obsidian/plugins/dataview/data.json"))
}

func TestAllowPath_WorkspaceAlwaysBlocked(t *testing.T) {
	f := allEnabled()
	assert.False(t, f.AllowPath(".obsidian/workspace.json"))
	assert.False(t, f.AllowPath(".obsidian/workspace-mobile.json"))
}

func TestAllowPath_AllEnabled(t *testing.T) {
	f := allEnabled()
	assert.True(t, f.AllowPath(".obsidian/app.json"))
	assert.True(t, f.AllowPath(".obsidian/appearance.json"))
	assert.True(t, f.AllowPath(".obsidian/hotkeys.json"))
	assert.True(t, f.AllowPath(".obsidian/core-plugins.json"))
	assert.True(t, f.AllowPath(".obsidian/community-plugins.json"))
	assert.True(t, f.AllowPath(".obsidian/plugins/foo/main.js"))
	assert.True(t, f.AllowPath(".obsidian/themes/bar/theme.css"))
	assert.True(t, f.AllowPath(".obsidian/snippets/custom.css"))
	assert.True(t, f.AllowPath(".obsidian/graph.json"))
}

func TestAllowPath_AllDisabled(t *testing.T) {
	f := allDisabled()
	assert.False(t, f.AllowPath(".obsidian"))
	assert.False(t, f.AllowPath(".obsidian/app.json"))
	assert.False(t, f.AllowPath(".obsidian/appearance.json"))
	assert.False(t, f.AllowPath(".obsidian/hotkeys.json"))
	assert.False(t, f.AllowPath(".obsidian/core-plugins.json"))
	assert.False(t, f.AllowPath(".obsidian/community-plugins.json"))
	assert.False(t, f.AllowPath(".obsidian/plugins/foo/main.js"))
	assert.False(t, f.AllowPath(".obsidian/themes/bar/theme.css"))
	assert.False(t, f.AllowPath(".obsidian/snippets/custom.css"))
	assert.False(t, f.AllowPath(".obsidian/graph.json"))
}

func TestAllowPath_BackslashPaths(t *testing.T) {
	f := allEnabled()

	// Paths with Windows-style backslashes should be normalized by
	// normalizePath before matching, so filter checks still work.
	assert.True(t, f.AllowPath(".obsidian\\app.json"))
	assert.True(t, f.AllowPath(".obsidian\\themes\\minimal\\theme.css"))
	assert.True(t, f.AllowPath(".obsidian\\plugins\\dataview\\main.js"))
	assert.True(t, f.AllowPath(".obsidian\\snippets\\custom.css"))
	assert.False(t, f.AllowPath(".obsidian\\workspace.json"))

	// Non-.obsidian backslash paths always allowed.
	assert.True(t, f.AllowPath("notes\\hello.md"))
	assert.True(t, f.AllowPath("folder\\sub\\file.txt"))

	// Disabled toggles still reject backslash paths.
	d := allDisabled()
	assert.False(t, d.AllowPath(".obsidian\\app.json"))
	assert.False(t, d.AllowPath(".obsidian\\plugins\\foo\\main.js"))
}

func TestAllowPath_SelectiveToggles(t *testing.T) {
	// Only main settings and hotkeys enabled.
	f := &SyncFilter{
		MainSettings: true,
		Hotkeys:      true,
	}
	assert.True(t, f.AllowPath(".obsidian"))
	assert.True(t, f.AllowPath(".obsidian/app.json"))
	assert.True(t, f.AllowPath(".obsidian/types.json"))
	assert.True(t, f.AllowPath(".obsidian/hotkeys.json"))
	assert.False(t, f.AllowPath(".obsidian/appearance.json"))
	assert.False(t, f.AllowPath(".obsidian/core-plugins.json"))
	assert.False(t, f.AllowPath(".obsidian/plugins/foo/main.js"))
	assert.False(t, f.AllowPath(".obsidian/themes/bar/theme.css"))
}
