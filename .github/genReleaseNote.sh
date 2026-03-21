#!/bin/bash

while getopts "v:" opt; do
  case $opt in
    v)
      version_range=$OPTARG
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
  esac
done

if [ -z "$version_range" ]; then
  echo "Please provide the version range using -v option. Example: ./genReleashNote.sh -v v1.14.1...v1.14.2"
  exit 1
fi

echo "## What's Changed" > release.md
git log --pretty=format:"* %h %s by @%an" --grep="^feat" -i $version_range | sort -f | uniq >> release.md
echo "" >> release.md

echo "## BUG & Fix" >> release.md
git log --pretty=format:"* %h %s by @%an" --grep="^fix" -i $version_range | sort -f | uniq >> release.md
echo "" >> release.md

echo "## Maintenance" >> release.md
git log --pretty=format:"* %h %s by @%an" --grep="^chore\|^docs\|^refactor" -i $version_range | sort -f | uniq >> release.md
echo "" >> release.md

echo "**Full Changelog**: https://github.com/MetaCubeX/mihomo/compare/$version_range" >> release.md
