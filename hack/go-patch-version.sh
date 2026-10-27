#!/usr/bin/env bash
#
# Keeps the go directive on the newest patch of the release series it already targets.
#
# Standard library security fixes ship in Go patch releases, so a module left on an older patch reports
# those vulnerabilities through govulncheck even when nothing in its dependency graph has changed. The
# release series itself is deliberately not advanced here, because a minor bump is a compatibility
# decision rather than a security one.
#
#   check   prints the current and the latest patch, exiting 1 when go.mod is behind
#   update  rewrites go.mod and the documented prerequisite to the latest patch

set -euo pipefail

go_mod="${GO_MOD:-go.mod}"
readme="${README:-README.md}"
releases_url="${RELEASES_URL:-https://go.dev/dl/?mode=json}"

# Prints the version named by the go directive, for example 1.27.3
current_patch() { awk '$1 == "go" && $2 ~ /^[0-9]/ { print $2; exit }' "$go_mod"; }

# Prints the release series a version belongs to, for example 1.27 for 1.27.3
series_of() { printf '%s\n' "$1" | cut -d. -f1,2; }

# Prints the newer of two versions, comparing each dotted field numerically
newer_of() { printf '%s\n%s\n' "$1" "$2" | sort -t. -k1,1n -k2,2n -k3,3n | tail -1; }

# Succeeds when every line of its input is a plain dotted version such as 1.27.3. Versions are written
# into sed expressions, so one that carries a delimiter, a newline or any other character would change
# the expression.
well_formed() { ! grep -Eqv '^[0-9]+\.[0-9]+(\.[0-9]+)?$'; }

# Prints the newest stable patch published for a release series. It fails when the feed names a
# version in the series that is not well formed, rather than trusting the rest of the feed.
latest_patch() {
    local versions
    versions="$(curl -fsSL "$releases_url" | jq -r --arg series "$1" '.[] | select(.stable) | .version | ltrimstr("go") | select(. == $series or startswith($series + "."))')"
    if [ -n "$versions" ] && ! printf '%s\n' "$versions" | well_formed; then
        echo "error: $releases_url names a release in the $1 series that is not a plain dotted version, so nothing is updated" >&2
        return 1
    fi
    printf '%s\n' "$versions" | sort -t. -k1,1n -k2,2n -k3,3n | tail -1
}

# Fails when a file carries no line matching a pattern, so an edit can never drift silently
require_line() {
    local path="$1" pattern="$2"
    if ! grep -Eq "$pattern" "$path"; then
        echo "error: no line matching /$pattern/ in $path, so it can no longer be updated automatically" >&2
        return 1
    fi
}

# Replaces every line matching a pattern
replace_line() {
    local path="$1" pattern="$2" replacement="$3" tmp
    tmp="$(mktemp)"
    sed -E "s|$pattern|$replacement|" "$path" >"$tmp"
    mv "$tmp" "$path"
}

mode="${1:-check}"
current="$(current_patch)"
if [ -z "$current" ]; then
    echo "error: no go directive found in $go_mod" >&2
    exit 1
fi
if ! printf '%s\n' "$current" | well_formed; then
    echo "error: $go_mod declares go $current, which is not a plain dotted version" >&2
    exit 1
fi

series="$(series_of "$current")"
latest="$(latest_patch "$series")"
if [ -z "$latest" ]; then
    echo "error: $releases_url lists no stable release in the $series series, which usually means the series is out of support and needs a minor bump by hand" >&2
    exit 1
fi

echo "current: $current"
echo "latest:  $latest"

if [ "$current" = "$latest" ] || [ "$(newer_of "$current" "$latest")" = "$current" ]; then
    echo "up to date"
    exit 0
fi

case "$mode" in
check)
    echo "behind: $go_mod declares $current but $latest is the newest patch in the $series series"
    exit 1
    ;;
update)
    # Both files are checked before either is written, so a stale pattern cannot leave a half applied bump.
    require_line "$go_mod" "^go $current\$"
    require_line "$readme" "^From source with Go $current or newer:"
    replace_line "$go_mod" "^go $current\$" "go $latest"
    replace_line "$readme" "^From source with Go $current or newer:" "From source with Go $latest or newer:"
    echo "updated $go_mod and $readme to $latest"
    ;;
*)
    echo "usage: $0 [check|update]" >&2
    exit 2
    ;;
esac
