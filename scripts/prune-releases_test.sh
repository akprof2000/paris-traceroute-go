#!/bin/bash
# Tests prune-releases.sh against a fake gh. Usage: scripts/prune-releases_test.sh
set -euo pipefail
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
cat > "$dir/gh" <<'FAKE'
#!/bin/bash
if [ "$1 $2" = "release list" ]; then
	cat "$FAKE_RELEASES"
elif [ "$1 $2" = "release delete" ]; then
	echo "$3" >> "$FAKE_DELETED"
fi
FAKE
chmod +x "$dir/gh"
export PATH="$dir:$PATH" FAKE_DELETED="$dir/deleted" FAKE_RELEASES="$dir/releases"
script="$(dirname "$0")/prune-releases.sh"
fail=0

run() { # releases-json keep expected-deleted...
	echo "$1" > "$FAKE_RELEASES"; : > "$FAKE_DELETED"
	KEEP=$2 bash "$script" > /dev/null
	shift 2
	got=$(sort "$FAKE_DELETED" | tr '\n' ' ')
	want=$(printf '%s\n' "$@" | sed '/^$/d' | sort | tr '\n' ' ')
	if [ "$got" = "$want" ]; then echo "PASS deleted [$got]"; else echo "FAIL deleted [$got], want [$want]"; fail=1; fi
}

five='[{"tagName":"v1.0.2","publishedAt":"2026-03-01T00:00:00Z"},
       {"tagName":"v1.0.0","publishedAt":"2026-01-01T00:00:00Z"},
       {"tagName":"v1.1.0","publishedAt":"2026-05-01T00:00:00Z"},
       {"tagName":"v1.0.1","publishedAt":"2026-02-01T00:00:00Z"},
       {"tagName":"v1.0.3","publishedAt":"2026-04-01T00:00:00Z"}]'
run "$five" 3 v1.0.0 v1.0.1
run "$five" 1 v1.0.0 v1.0.1 v1.0.2 v1.0.3
run "$five" 5 ""
run '[{"tagName":"v1.0.0","publishedAt":"2026-01-01T00:00:00Z"}]' 3 ""
run '[]' 3 ""
exit $fail
