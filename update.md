# Versioning and update

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

**Table of Contents** _generated with [DocToc](https://github.com/thlorenz/doctoc)_

-   [How do we keep update to date with upstream](#how-do-we-keep-update-to-date-with-upstream)
-   [How do we version this repo](#how-do-we-version-this-repo)
-   [How do we make release](#how-do-we-make-release)

## How do we keep update to date with upstream

> Rule of thumb: We keep all IBM related commits on top of the upstream code using rebase and/or cherry-pick.

1. Clone both [upstream](https://github.com/Yelp/detect-secrets) and [IBM version](https://github.com/IBM/detect-secrets)

    ```sh
    git clone git@github.com:IBM/detect-secrets.git
    cd detect-secrets
    git remote add upstream-github git@github.com:Yelp/detect-secrets.git
    git fetch --all
    ```

1. Rebase IBM changes on top of upstream code

    1. Rebase on top of upstream `master` branch.

        ```sh
        git checkout -b pick-upstream master
        git rebase upstream-github/master
        # Fix conflicts and make sure tests are passing
        ```

    1. (Optional) rearrange IBM related commits with `git rebase -i $(git log -n1 upstream-github/master --pretty=format:"%h")`. You can move around and squash IBM commits to make the IBM specific commits at a low number. It helps with future rebase. To manually identify the base commit (the commit before first IBM commit), you can search for IBM's first commit with title `Apply IBM specific changes`. It's not encouraged to use commit hash to identify the change since the commit hash would change during rebase process.

1. Push change to GHE

    ```sh
    git push origin pick-upstream
    ```

1. Create pull requset and ask team mate to review

    1. Create pull request based on `pick-upstream` branch
    1. Invite team mates to review
    1. Get an approval from team mates

1. Repo admin force push reviewed change to `master`
    1. Since we altered the commit hash during rebase process, it's unlikely pull request can auto merge. Hence we choose to use force push to keep `master` history cleaner.
    1. Repo admin [turns off](https://help.github.com/en/enterprise/admin/developer-workflow/configuring-protected-branches-and-required-status-checks) protected branch for `master`
    1. Repo admin force push with `git push origin pick-upstream:master -f`
    1. Repo admin [turns protected branch back on](https://help.github.com/en/enterprise/admin/developer-workflow/configuring-protected-branches-and-required-status-checks). Make sure `Travis` and `detect-secrets` checks are required.
1. (Optional) [Create a new release](#how-do-we-make-release)

## How do we version this repo

Format: `<upstream-version>-ibm.<minor>.<fix>`, for example `0.12.0-ibm.3`

1. When adding new IBM specific feature, increase `<minor>`
1. When fixing IBM specific bugs, increase `<fix>`
1. When rebase from upstream, update `<upstream-version>` to the rebased upstream version. We do not reset the `<minor>` and `<fix>` when bumping upstream version.
1. Version number also needs to be updated in [`__init__.py`](./detect_secrets/__init__.py#L1)

## How do we make release

Release should be made when we bump to a new version.

1. Use [`hub` tool](https://github.com/github/hub) to create new release. You can view the released version at <https://github.ibm.com/Whitewater/whitewater-detect-secrets/releases>.
   This process also creates a tag, which triggers Traivs tag build to generate a new version of the docker image labeled with the newly created tag.

```sh
# <branch-name>: the latest commit from the branch would be used to create tag.
# <version>: match the version in detect_secrets/__init__.py
$ hub release create -t <branch-name> <version>

# You will be prompt to input a release note. First line would be the title and
# following text would be release content.
#
#   Release title follows format "Release <version>"
#   Release text contains the features, fixes introduced in the new release
```
