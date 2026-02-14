# Obsidian MCP Server Improvements

## Context
Issues and feature requests identified during real-world usage session with Claude.

## Bugs / Issues

### 1. New files/folders intermittently not picked up by Obsidian filewatcher
**What happened:** Created `Projects/obsidian-mcp-improvements.md` via `vault_write`. File existed in Docker volume but Obsidian didn't show it in the file browser.
**Reproducibility:** Intermittent. Subsequent test with `TestFolder/test-file.md` synced immediately. Rewrites also sync fine.
**Likely cause:** Unknown — possibly timing, possibly specific conditions.
**Notes:** Keep an eye on this. May not need fixing if it was a one-off.

### 2. vault_edit fails with "No approval received"
**What happened:** Called `vault_edit` on `Templates/weekly_organiser_template.md` twice, both times failed with "No approval received". Also failed when trying to edit this very document.
**Workaround used:** Fell back to `vault_write` to replace the entire file.
**Questions:** Is this a timeout? Permissions issue? Something in the approval flow?

### 3. vault_search intermittent error
**What happened:** Search for "1-1 template" returned "Error occurred during tool execution". Other searches (e.g. "organiser") worked fine.
**No workaround:** Had to use `vault_list` on the Templates folder instead.

---

## New Features Needed

### 1. vault_delete (High Priority)
**Use case:** Needed to delete 221 files across 3 folders (old Xiatech entries when starting new job).
**Suggested signature:**
```
vault_delete
  path: string (required) - file path relative to vault root
```
**Notes:** Should probably refuse to delete folders (or require a separate function/flag for that).

### 2. vault_delete_batch (High Priority)
**Use case:** Same as above — deleting 97 + 77 + 47 files one at a time would be painful.
**Suggested signature:**
```
vault_delete_batch
  paths: string[] (required) - array of file paths relative to vault root
```
**Alternative:** Could support glob patterns instead, e.g. `IPH/Organiser/DB/Entries/*.md`

### 3. vault_move / vault_rename (Medium Priority)
**Use case:** User moved folders from `Work/` to `IPH/` manually, then I had to fix all the references in the files. Would be cleaner if the MCP could do the move and the user's Obsidian links updated automatically.
**Suggested signature:**
```
vault_move
  from_path: string (required) - source path
  to_path: string (required) - destination path
```
**Notes:** Should work for both files and folders. Obsidian may have APIs that handle link updating automatically.

### 4. vault_copy (Low Priority)
**Use case:** Duplicating templates, backing up before destructive edits.
**Suggested signature:**
```
vault_copy
  from_path: string (required) - source path
  to_path: string (required) - destination path
```

---

## Summary

| Item | Type | Priority |
|------|------|----------|
| Filewatcher intermittent | Bug | Low (monitor) |
| vault_edit approval failure | Bug | High |
| vault_search intermittent error | Bug | Medium |
| vault_delete | Feature | High |
| vault_delete_batch | Feature | High |
| vault_move / vault_rename | Feature | Medium |
| vault_copy | Feature | Low |
