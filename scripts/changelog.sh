#!/usr/bin/env bash
#
# Builds the changelog from conventional commits in the git history.
#
# The same code is used in two places, so the sections in CHANGELOG.md and in
# the body of a GitHub Release match by construction:
#   * `--all` — the whole file (this is how CHANGELOG.md was backfilled);
#   * no arguments — the body of the section for the next release, which
#     `release.yml` puts into the release notes.
#
# Usage:
#   scripts/changelog.sh                        # section body: last tag..HEAD
#   scripts/changelog.sh --heading              # the same plus "## [version] - date"
#   scripts/changelog.sh --insert               # insert the version section into CHANGELOG.md
#   scripts/changelog.sh --range v1.0.0..v1.1.0
#   scripts/changelog.sh --version 2.1.0        # version in the heading (otherwise from Cargo.toml)
#   scripts/changelog.sh --all > CHANGELOG.md   # regenerate the whole file
#
# The mapping of commit types onto sections lives in `bucket_for`.

set -euo pipefail

readonly REPO_URL="https://github.com/filipov-dev/jwks-service-app"

# Sections in output order: key and heading. Empty sections are not printed, so
# most versions have two or three.
readonly SECTIONS=(
    "breaking:Breaking changes"
    "added:Added"
    "changed:Changed"
    "fixed:Fixed"
    "security:Security"
    "docs:Documentation"
    "internal:Internal"
    "other:Other"
)

usage() {
    sed -n '3,19p' "$0" | sed 's/^# \{0,1\}//'
}

# The section a commit of the given type falls into.
#
# Keep a Changelog describes six sections for user-facing changes. Two more are
# added here: "Documentation" (docs commits in this project are client examples
# and operations instructions, which face the consumer too) and "Internal" (CI,
# tests, formatting). Without the latter, releases that carried only a workflow
# fix would look empty.
bucket_for() {
    case "$1" in
        feat) echo added ;;
        fix) echo fixed ;;
        security) echo security ;;
        perf | revert) echo changed ;;
        docs) echo docs ;;
        # `deps` is the prefix of dependabot commits. Without it, dependency
        # updates would land in "Other".
        refactor | style | test | ci | build | chore | deps) echo internal ;;
        *) echo other ;;
    esac
}

# Parses the commit subjects of a range and spreads them over per-section files
# in directory $2. A file exists only for a non-empty section.
collect() {
    local range="$1" dir="$2"
    local subject type scope bang text entry bucket

    rm -rf "$dir"
    mkdir -p "$dir"

    # --reverse: within a release the changes read in the order they were made.
    # --format (not --pretty=format) so that the last line ends with a newline
    # and is not lost by read.
    while IFS= read -r subject; do
        [ -n "$subject" ] || continue

        if [[ $subject =~ ^([a-z]+)(\(([^\)]+)\))?(!)?:[[:space:]]+(.+)$ ]]; then
            type="${BASH_REMATCH[1]}"
            scope="${BASH_REMATCH[3]}"
            bang="${BASH_REMATCH[4]}"
            text="${BASH_REMATCH[5]}"
        else
            # Early history (before conventional commits were adopted): subjects
            # like "JWKSAPP-7: Implement the JWKS Standard correctly". Those go
            # to "Other" instead of being dropped.
            type="_plain"
            scope=""
            bang=""
            text="$subject"
        fi

        if [ -n "$scope" ]; then
            entry="- **${scope}**: ${text}"
        else
            entry="- ${text}"
        fi

        # An exclamation mark in the type (`feat!:`) means a break of backward
        # compatibility per the conventional commits spec. Such changes matter
        # more than their category and are pulled into a separate section on
        # top.
        if [ -n "$bang" ]; then
            bucket=breaking
        else
            bucket="$(bucket_for "$type")"
        fi

        printf '%s\n' "$entry" >>"${dir}/${bucket}"
    done < <(git log --no-merges --reverse --format='%s' "$range")
}

# Prints the non-empty sections from directory $1.
emit() {
    local dir="$1" pair key title printed=0

    for pair in "${SECTIONS[@]}"; do
        key="${pair%%:*}"
        title="${pair#*:}"

        [ -s "${dir}/${key}" ] || continue

        printf '### %s\n\n' "$title"
        cat "${dir}/${key}"
        printf '\n'
        printed=1
    done

    [ "$printed" = 1 ] || printf '_No changes._\n\n'
}

# Whether range $1 holds any commit at all (merge commits aside).
has_commits() {
    [ -n "$(git log --no-merges --format='%s' "$1")" ]
}

# The section body for range $1.
section_body() {
    local dir
    dir="$(mktemp -d)"
    collect "$1" "$dir"
    emit "$dir"
    rm -rf "$dir"
}

# Tags in ascending version order. There are fewer releases than version bumps:
# within a pull request every commit bumps the version, but only one tag is cut,
# on the final one. Hence the gaps in the list; they are not lost history, their
# commits belong to the next released tag.
tags_ascending() {
    git tag --sort=v:refname
}

# The date of the commit a ref points at.
ref_date() {
    git log -1 --format=%ad --date=short "$1"
}

version_from_cargo() {
    grep -m1 '^version' Cargo.toml | cut -d '"' -f 2
}

# The last released tag — the starting point for the next release.
last_tag() {
    tags_ascending | tail -n 1
}

# The whole file: header, "Unreleased" (when there are commits after the last
# tag), then versions from new to old and the compare links between tags.
render_all() {
    local tags=() tag prev range i

    while IFS= read -r tag; do
        tags+=("$tag")
    done < <(tags_ascending)

    cat <<'HEADER'
# Changelog

All notable changes to this project. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/).

This file is built from the commit history and is regenerated with
`scripts/changelog.sh --all`; the body of every GitHub Release is built by the
same script. The entries are commit subjects verbatim, with the tracker issue
key in parentheses.

Two sections are added to the six of Keep a Changelog: "Documentation" (client
examples and operations instructions — changes for the consumer of the service)
and "Internal" (CI, tests, formatting).

HEADER

    # The "Unreleased" section shows up only when something has actually piled
    # up after the last tag: right after a release on master there is none.
    if has_commits "$(last_tag)..HEAD"; then
        printf '## [Unreleased]\n\n'
        section_body "$(last_tag)..HEAD"
    fi

    for ((i = ${#tags[@]} - 1; i >= 0; i--)); do
        tag="${tags[$i]}"

        if [ "$i" -gt 0 ]; then
            prev="${tags[$((i - 1))]}"
            range="${prev}..${tag}"
        else
            range="$tag"
        fi

        printf '## [%s] - %s\n\n' "${tag#v}" "$(ref_date "$tag")"
        section_body "$range"
    done

    # Version compare links: from a "## [2.0.1]" heading the diff is one click
    # away.
    printf '[Unreleased]: %s/compare/%s...HEAD\n' "$REPO_URL" "$(last_tag)"
    for ((i = ${#tags[@]} - 1; i >= 0; i--)); do
        tag="${tags[$i]}"

        if [ "$i" -gt 0 ]; then
            printf '[%s]: %s/compare/%s...%s\n' \
                "${tag#v}" "$REPO_URL" "${tags[$((i - 1))]}" "$tag"
        else
            printf '[%s]: %s/releases/tag/%s\n' "${tag#v}" "$REPO_URL" "$tag"
        fi
    done
}

# Inserts the section of version $1 (range $2) into CHANGELOG.md: both the
# section itself, after the header, and the compare link in the block at the
# bottom.
#
# This is needed because the version is bumped in the same pull request as the
# change, while the tag appears only after the merge. Regenerating with `--all`
# at that moment would put the commits under "Unreleased" — a section carrying
# the version number can only be produced this way.
insert_section() {
    local version="$1" range="$2" file=CHANGELOG.md
    local head body links tmp prev

    if grep -q "^## \[${version}\]" "$file"; then
        echo "section [${version}] is already in ${file}" >&2
        return 1
    fi

    tmp="$(mktemp -d)"

    # The file splits into three parts: the header up to the first section, the
    # sections, and the link block. The new section goes on top of the sections
    # — Keep a Changelog wants reverse chronological order.
    head="${tmp}/head"
    body="${tmp}/body"
    links="${tmp}/links"

    awk -v head="$head" -v body="$body" -v links="$links" '
        /^## \[/ { part = 2 }
        /^\[[^]]+\]: http/ { if (part != 3) part = 3 }
        { print > (part == 3 ? links : part == 2 ? body : head) }
    ' part=1 "$file"

    prev="$(last_tag)"

    {
        cat "$head"
        printf '## [%s] - %s\n\n' "$version" "$(date +%F)"
        section_body "$range"
        cat "$body"
        # The "Unreleased" line is always first in the link block; it is
        # rewritten to start from the version being inserted, and the new
        # version's own compare link goes right after it. Both point at a tag
        # that release.yml cuts on merge.
        printf '[Unreleased]: %s/compare/v%s...HEAD\n' "$REPO_URL" "$version"
        printf '[%s]: %s/compare/%s...v%s\n' "$version" "$REPO_URL" "$prev" "$version"
        tail -n +2 "$links"
    } >"${tmp}/out"

    mv "${tmp}/out" "$file"
    rm -rf "$tmp"

    echo "added section [${version}] to ${file}" >&2
}

main() {
    local mode=section range="" version="" heading=0

    while [ $# -gt 0 ]; do
        case "$1" in
            --all)
                mode=all
                shift
                ;;
            --insert)
                mode=insert
                shift
                ;;
            --heading)
                heading=1
                shift
                ;;
            --range)
                range="$2"
                shift 2
                ;;
            --version)
                version="$2"
                shift 2
                ;;
            -h | --help)
                usage
                return 0
                ;;
            *)
                echo "unknown argument: $1" >&2
                usage >&2
                return 2
                ;;
        esac
    done

    if [ "$mode" = all ]; then
        render_all
        return 0
    fi

    if [ -z "$range" ]; then
        local from
        from="$(last_tag)"
        # The very first release in a repository without tags — take the whole
        # history.
        range="${from:+${from}..}HEAD"
    fi

    if [ "$mode" = insert ]; then
        [ -n "$version" ] || version="$(version_from_cargo)"
        insert_section "$version" "$range"
        return 0
    fi

    if [ "$heading" = 1 ]; then
        [ -n "$version" ] || version="$(version_from_cargo)"
        printf '## [%s] - %s\n\n' "$version" "$(date +%F)"
    fi

    section_body "$range"
}

main "$@"
