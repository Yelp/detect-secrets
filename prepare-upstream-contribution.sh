#!/bin/bash
# Description:
#
# This script allows you to generate a baseline commit history maintains the
# original author / committor information before making upstream contribution.
# Inspired by https://stosb.com/blog/retaining-history-when-moving-files-across-repositories-in-git/
#
# See usage for more detailed description.

function usage() {
cat <<DOCEND
Description:

  This script takes a list of file as input. Find out all the commits containing the input
  file list, then rewrites the history from START_COMMIT to END_COMMIT, removing all commits
  does not contain file within input file list. For the remaining commits, trim out all the
  changes not applied to input file list. The end result is a commit history after START_COMMIT,
  all commits are specific for input file list.

  Note: after you get a rewrite history, you might want to review it and use 'git rebase' to get
  an even cleaner history.

Environment variables:

  START_COMMIT   default is the commit right before message "Apply IBM specific changes".
                 This commit won't be changed.
  END_COMMIT     default is "head" which is the last commit to be rewrite.

Parameters:

  List of files to collect commits from

Example:

  env START_COMMIT=a3a8b85 END_COMMIT=head ./prepare-upstream-contribution.sh detect_secrets/plugins/softlayer.py tests/plugins/softlayer_test.py
DOCEND
  exit 1
}

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
  usage
fi

echo "File to filter is ${FILES:=$@}"
if [ -z "$FILES" ]; then
  echo "Incoming file list is empty"
  exit 1
fi

echo "START_COMMIT is ${START_COMMIT:=$(git log --grep='Apply IBM specific changes' --pretty=format:'%h')~1}"
echo "END_COMMIT is ${END_COMMIT:=head}"
echo "Temp branch is ${TEMP_BRANCH:=rewrite-$(head /dev/urandom | base64 | tr -dc a-z0-9 | head -c8)}"

TEMP_GIT_DIR=${TEMP_BRANCH}-newroot
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
git checkout -b ${TEMP_BRANCH}

# Use filter to copy file to a temporarity location
git filter-branch --force --prune-empty --tree-filter "mkdir -p ${TEMP_GIT_DIR}; for f in $FILES; do mv \$f ${TEMP_GIT_DIR}/ 2>/dev/null; done; true;" ${START_COMMIT}..${END_COMMIT}
# Set the temp location as root
git filter-branch --prune-empty -f --subdirectory-filter ${TEMP_BRANCH}-newroot
# Add filtered off commits to the top of starting commit
git rebase ${START_COMMIT}

# move files back to their original location and make a new commit
for f in $FILES; do
    mv $(basename $f) $f 2>/dev/null
    git add $f
    git add $(basename $f)
done
git commit -m 'Move files back'
git checkout ${CURRENT_BRANCH}

echo "The prepared branch is ${TEMP_BRANCH}. Use command below to view the history"
echo ""
echo "  git log --oneline -n10 ${TEMP_BRANCH}"
echo ""
