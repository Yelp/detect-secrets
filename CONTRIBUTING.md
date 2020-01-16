## Contributing

[fork]: /fork
[pr]: /compare
[style]: https://standardjs.com/
[code-of-conduct]: CODE_OF_CONDUCT.md

Hi there! We're thrilled that you'd like to contribute to this project. Your help is essential for keeping it great.

Please note that this project is released with a [Contributor Code of Conduct][code-of-conduct]. By participating in this project you agree to abide by its terms.

We are looking into contributing back the changes to the upstream project. Try not to include anything we want to keep private. If it does include something we want to keep private please indicate it in the PR. The details will be figured out how we are going to contribute back will come later.

## Changes we are looking for

We are looking for all sorts of changes. The changes will be broken down into 2 pieces:

1. Changes to the operations/flow of the tool. These are changes don't affect what secrets are found, but affect how the tool is used.
1. Changes to the secrets detection logic. This changes which secrets are going to be detected.

Which type to change is up to you to decide. If you are passionate about detecting secrets, then work on the logic. If you passionate about the UX or how to tool is used, then make a change to the operation/flow aspect of the tool.

## Issues and PRs

If you have suggestions for how this project could be improved, or want to report a bug, open an issue! We'd love all and any contributions. If you have questions, too, we'd love to hear them.

We'd also love PRs. If you're thinking of a large PR, we advise opening up an issue first to talk about it, though! Look at the links below if you're not sure how to open a PR.

## Submitting a pull request

1. [Fork][fork] and clone the repository.
1. Configure and install the dependencies as described in the [README.md](/README.md).
1. Make sure the tests pass on your machine as described in the [README.md](/README.md).
1. Create a new branch: `git checkout -b my-branch-name`.
1. Make your change, add tests, and make sure the tests still pass.
1. Push to your fork and [submit a pull request][pr].
1. Pat your self on the back and wait for your pull request to be reviewed and merged.

Here are a few things you can do that will increase the likelihood of your pull request being accepted:

- Write and update tests.
- Keep your changes as focused as possible. If there are multiple changes you would like to make that are not dependent upon each other, consider submitting them as separate pull requests.
- Write a [good commit message](http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html).

Work in Progress pull requests are also welcome to get feedback early on, or if there is something blocked you.

## Resources

- [How to Contribute to Open Source](https://opensource.guide/how-to-contribute/)
- [Using Pull Requests](https://help.github.com/articles/about-pull-requests/)
- [GitHub Help](https://help.github.com)

## Process for Adding a New Secret Detector to whitewater-detect-secrets
There are two key steps for developing a new secret detector: secret identification and secret verification.
It is often easier to review contributions if these two steps are submitted as separate PRs, although this is not mandatory.
The processes for each of these two steps are outlined below.

### Secret Identification
- Develop an understanding of all the secret types for a given service. A service may have combinations of basic-auth, IAM auth, tokens, keys, passwords, and / or other proprietary authentication methods.
- Identify any specification documents from the service provider for the use & format of the secret types to be captured.
- Develop an understanding of the API / service call uses.
  - Is it purely RESTful, or are there prevalent SDKs which should be accounted for and detected?
- Search / identify examples of the signature and use cases in github.ibm.com or create your own.
  - Iterate until you have sufficient representation of the different ways in which the secret may be used.
- Using the other detectors under `detect-secrets/plugins` as examples, create a new Python file under that path. The file should contain a new detector class which inherits from `RegexBasedDetector`.
- Write one or more regexes to match and capture secrets when found within the use cases identified above. Assign a list of regexes to the `denylist` variable. We have created helper functions to make this easier, which may be seen in the existing detectors.
- If multiple factors exist, identify a primary factor to capture with the `denylist` regexes. Secondary factors will be captured as part of the verification process below.
- Create test cases to ensure that example secrets matching the (primary factor's) secret signature will be caught. Use the test files under `tests/plugins` as examples.

### Secret Verification
- Identify a service endpoint (API or SDK) to which the potentially multiple factors of the secret can be presented for verification.
  - In complex cases (where the service is hosted internally), it's often helpful to identify an IBM SME who can help navigate the API / SDK spec of the service for verification purposes. [w3 ProductPages](https://productpages.w3ibm.mybluemix.net/ProductPages/index.html) is a good resource to help identify an SME.
  - Note: if there are _many_ signature hits, it may create a stressful load on the verification endpoint, so a key design point is to minimize false positive cases.
- Using the existing plugins in `detect_secrets/plugins` as examples, add the `verify()` function to your detector. The `verify` function should validate a found secret with the service endpoint and determine whether it is active or not, returning either `VerifiedResult.VERIFIED_TRUE` or `VerifiedResult.VERIFIED_FALSE`. `verify()` may also return `VerifiedResult.UNVERIFIED` if verification cannot be completed due to issues like endpoint availability, lack of expected data elements, etc.
- If multiple factors must be found to verify the secret, write an additional helper function to scan the context lines surrounding the primary factor. One or more additional regexes may be required. Context lines are passed to the `verify()` function as `content`. The number of context lines pulled from above and below the primary factor is defined in `plugins/base.py` as the global variable `LINES_OF_CONTEXT`.
- Using the existing tests in `tests/plugins` as examples, create test cases for positive and negative verification results, considering required factors & return codes. Note that you should mock responses from the service endpoint to avoid actually calling it during tests.
