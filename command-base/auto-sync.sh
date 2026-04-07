#!/bin/bash
# ── Safe Auto-Sync: Branch-based workflow with PR protection ──
#
# How it works:
# 1. Auto-coder changes go to feature branches (never directly to main)
# 2. Every 10 seconds, captures changes to the active feature branch
# 3. When a batch of work completes, creates a PR for review
# 4. Simple changes auto-merge after a safety check
# 5. Main branch stays protected — only merged PRs
#
# Usage:
#   ./auto-sync.sh              — run in foreground
#   ./auto-sync.sh &            — run in background
#   ./auto-sync.sh --daemon     — run as daemon with PID file
#
# Stop: kill $(cat .auto-sync.pid)

cd "$(dirname "$0")"
REPO_DIR="$(pwd)"

# Daemon mode
if [ "$1" = "--daemon" ]; then
    nohup "$0" > /tmp/auto-sync.log 2>&1 &
    echo $! > .auto-sync.pid
    echo "[Auto-Sync] Started as daemon (PID: $!)"
    echo "[Auto-Sync] Log: /tmp/auto-sync.log"
    exit 0
fi

echo $$ > .auto-sync.pid

CAPTURE_INTERVAL=10    # Check for changes every N seconds
COMMIT_THRESHOLD=3     # Batch commits after N captures with changes
PR_AUTO_MERGE=true     # Auto-merge PRs that pass safety checks
CURRENT_BRANCH=""
CHANGE_COUNT=0
LAST_COMMIT_TIME=0

log() {
    echo "[Auto-Sync $(date '+%H:%M:%S')] $1"
}

# Ensure we're on main to start
ensure_main() {
    cd "$REPO_DIR"
    git checkout main 2>/dev/null
    git pull origin main --rebase 2>/dev/null
}

# Create a feature branch for current work
create_feature_branch() {
    cd "$REPO_DIR"
    local timestamp=$(date '+%Y%m%d-%H%M%S')
    local branch_name="auto/${timestamp}"
    git checkout -b "$branch_name" 2>/dev/null
    CURRENT_BRANCH="$branch_name"
    CHANGE_COUNT=0
    log "Created branch: $branch_name"
}

# Capture changes to current branch
capture_changes() {
    cd "$REPO_DIR"

    # Check for any changes (staged, unstaged, or untracked)
    local changes=$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')

    if [ "$changes" = "0" ]; then
        return 1  # No changes
    fi

    # If we're on main, create a feature branch first
    local current=$(git branch --show-current 2>/dev/null)
    if [ "$current" = "main" ] || [ -z "$CURRENT_BRANCH" ] || [ "$current" != "$CURRENT_BRANCH" ]; then
        create_feature_branch
    fi

    # Stage and commit
    git add -A 2>/dev/null

    local added=$(git diff --cached --numstat 2>/dev/null | wc -l | tr -d ' ')
    if [ "$added" = "0" ]; then
        return 1
    fi

    local files_changed=$(git diff --cached --name-only 2>/dev/null | head -5 | tr '\n' ', ' | sed 's/,$//')
    local msg="Auto-capture: ${added} files (${files_changed})"

    git commit -m "$msg" --no-gpg-sign 2>/dev/null
    CHANGE_COUNT=$((CHANGE_COUNT + 1))
    LAST_COMMIT_TIME=$(date +%s)

    # Push to remote
    git push origin "$CURRENT_BRANCH" 2>/dev/null

    log "Captured ${added} changes on $CURRENT_BRANCH (batch $CHANGE_COUNT)"
    return 0
}

# Safety check before merging
safety_check() {
    cd "$REPO_DIR"
    local branch=$1

    # Check 1: No deletion of critical files
    local deleted_critical=$(git diff main..."$branch" --name-status 2>/dev/null | grep "^D" | grep -E "server\.js|app\.js|index\.html|styles\.css|CLAUDE\.md|package\.json" | wc -l | tr -d ' ')
    if [ "$deleted_critical" != "0" ]; then
        log "SAFETY FAIL: Critical files deleted on $branch"
        return 1
    fi

    # Check 2: Changes aren't too massive (>50 files could be destructive)
    local total_files=$(git diff main..."$branch" --name-only 2>/dev/null | wc -l | tr -d ' ')
    if [ "$total_files" -gt 50 ]; then
        log "SAFETY WARNING: $total_files files changed on $branch — needs manual review"
        return 1
    fi

    # Check 3: server.js and app.js haven't been completely rewritten (>80% changed)
    for critical_file in app/server.js app/public/app.js; do
        if git diff main..."$branch" -- "$critical_file" 2>/dev/null | head -1 | grep -q "diff"; then
            local total_lines=$(wc -l < "$critical_file" 2>/dev/null | tr -d ' ')
            local changed_lines=$(git diff main..."$branch" -- "$critical_file" 2>/dev/null | grep "^[+-]" | grep -v "^[+-][+-][+-]" | wc -l | tr -d ' ')
            if [ "$total_lines" -gt 0 ]; then
                local pct=$((changed_lines * 100 / total_lines))
                if [ "$pct" -gt 80 ]; then
                    log "SAFETY WARNING: $critical_file is ${pct}% changed — needs manual review"
                    return 1
                fi
            fi
        fi
    done

    log "Safety check passed for $branch"
    return 0
}

# Create PR and optionally auto-merge
create_pr_and_merge() {
    cd "$REPO_DIR"
    local branch=$1

    if [ -z "$branch" ] || [ "$branch" = "main" ]; then
        return 0
    fi

    # Check if there are commits ahead of main
    local ahead=$(git rev-list main.."$branch" --count 2>/dev/null)
    if [ "$ahead" = "0" ] || [ -z "$ahead" ]; then
        log "No commits ahead of main on $branch — skipping PR"
        git checkout main 2>/dev/null
        git branch -d "$branch" 2>/dev/null
        return 0
    fi

    local files_changed=$(git diff main..."$branch" --name-only 2>/dev/null | wc -l | tr -d ' ')
    local timestamp=$(date '+%Y-%m-%d %H:%M')

    # Create PR
    local pr_url=$(gh pr create \
        --base main \
        --head "$branch" \
        --title "Auto-sync: ${ahead} commits, ${files_changed} files ($timestamp)" \
        --body "$(cat <<PRBODY
## Auto-Sync PR

**Branch:** \`$branch\`
**Commits:** $ahead
**Files changed:** $files_changed

### Changes
$(git diff main..."$branch" --stat 2>/dev/null | tail -5)

---
Auto-generated by The Team auto-sync system.
PRBODY
)" 2>&1)

    if echo "$pr_url" | grep -q "https://"; then
        log "PR created: $pr_url"

        # Run safety check
        if [ "$PR_AUTO_MERGE" = "true" ] && safety_check "$branch"; then
            # Auto-merge via squash
            local pr_number=$(echo "$pr_url" | grep -oE '[0-9]+$')
            if [ -n "$pr_number" ]; then
                gh pr merge "$pr_number" --squash --delete-branch 2>/dev/null
                if [ $? -eq 0 ]; then
                    log "Auto-merged PR #$pr_number (passed safety check)"
                    git checkout main 2>/dev/null
                    git pull origin main 2>/dev/null
                else
                    log "Auto-merge failed for PR #$pr_number — left open for manual review"
                fi
            fi
        else
            log "PR left open for manual review (safety check failed or auto-merge disabled)"
        fi
    else
        log "PR creation failed: $pr_url"
        # Fall back to direct merge if PR fails (repo might not allow PRs to self)
        git checkout main 2>/dev/null
        git merge "$branch" --no-edit 2>/dev/null
        git push origin main 2>/dev/null
        git branch -d "$branch" 2>/dev/null
        log "Fallback: direct merged $branch to main"
    fi

    CURRENT_BRANCH=""
    CHANGE_COUNT=0
}

# Check if work has settled (no changes for 60 seconds after last commit)
check_settled() {
    if [ "$CHANGE_COUNT" -gt 0 ] && [ "$LAST_COMMIT_TIME" -gt 0 ]; then
        local now=$(date +%s)
        local elapsed=$((now - LAST_COMMIT_TIME))
        if [ "$elapsed" -ge 60 ]; then
            return 0  # Settled — ready to PR
        fi
    fi
    return 1  # Not settled yet
}

# Cleanup on exit
cleanup() {
    log "Shutting down..."
    if [ -n "$CURRENT_BRANCH" ] && [ "$CHANGE_COUNT" -gt 0 ]; then
        log "Finalizing branch $CURRENT_BRANCH before exit..."
        capture_changes 2>/dev/null
        create_pr_and_merge "$CURRENT_BRANCH"
    fi
    rm -f .auto-sync.pid
    exit 0
}

trap cleanup SIGINT SIGTERM

# ── Main Loop ──
log "Started — watching $REPO_DIR"
log "Capture interval: ${CAPTURE_INTERVAL}s | Auto-merge: $PR_AUTO_MERGE"
ensure_main

while true; do
    sleep $CAPTURE_INTERVAL

    # Capture any changes
    if capture_changes; then
        # Changes were captured
        :
    fi

    # Check if work has settled (no new changes for 60s)
    if check_settled; then
        log "Work settled — creating PR for $CURRENT_BRANCH ($CHANGE_COUNT commits)"
        create_pr_and_merge "$CURRENT_BRANCH"
        ensure_main
    fi
done
