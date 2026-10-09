#!/bin/bash
# Deletes all but the KEEP most recent published releases, with their tags.
# Drafts are left alone. Needs gh (authenticated) and jq.
# Usage: KEEP=3 [DRY_RUN=1] [GH_REPO=owner/repo] scripts/prune-releases.sh
set -euo pipefail
KEEP=${KEEP:-3}
DRY_RUN=${DRY_RUN:-0}

# tr strips the CRs jq prints on Windows.
old=$(gh release list --exclude-drafts --limit 1000 --json tagName,publishedAt |
	jq -r --argjson keep "$KEEP" 'sort_by(.publishedAt) | reverse | .[$keep:] | .[].tagName' |
	tr -d '\r')

if [ -z "$old" ]; then
	echo "nothing to prune: at most $KEEP releases"
	exit 0
fi
for tag in $old; do
	if [ "$DRY_RUN" = 1 ]; then
		echo "would delete release $tag"
	else
		echo "deleting release $tag"
		gh release delete "$tag" --yes --cleanup-tag
	fi
done
