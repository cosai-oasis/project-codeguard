# Contributing 

## How to contribute?

The [Coalition for Secure AI (CoSAI)](https://www.coalitionforsecureai.org/) is an open-source project that is actively seeking contributions from any willing participants. Here are some guidelines for people that would like to contribute to the project.

In general, a CoSAI Contributor is expected to:
* be knowledgeable in one or more fields related to the project
* contribute to the developing and finalizing the workstream deliverables
* be reliable in completing issues to which they have been assigned
* show commitment over time with one or more PRs merged
* follow the project style and testing guidelines
* follow branch, PR, and code style conventions
* contribute in ways that substantially improve the quality of the project and the experience of people who use it

When contributing to any CoSAI repository, please first discuss the change you wish to make via a Github Issue, or in an email to the specific Workstream mailing list.

Please note this project follows the [OASIS Participants Code of Conduct](https://www.oasis-open.org/policies-guidelines/oasis-participants-code-of-conduct/); please be respectful of differing opinions when discussing potential contributions.

### First-time contributors

If you are new to the CoSAI project and are looking for an entry-point to make your first contribution, look at the open issues. Issues that are tagged with `good first issues` are meant to be small pieces of work that a first-time contributor can pick-up and complete. If you find one that you'd like to work on, please assign yourself or comment on the issue and one of the maintainers can assign it for you.

## Submitting a new issue

If you want to create a new issue that doesn't exist already, just open a new one. See [here how to do that](https://github.com/cosai-oasis/cosai-tsc/blob/main/.github/ISSUE_TEMPLATE/issue.md) and follow the guidelines in one of our [issue templates](https://github.com/cosai-oasis/cosai-tsc/blob/main/.github/ISSUE_TEMPLATE/issue.md).

## Submitting a new pull request

Follow these steps when submitting a pull request:

1. Fork this repo into your GitHub account. Read more about [forking a repo on Github here](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/fork-a-repo).
2. Create a new branch, based on the `main` branch, with a name that concisely describes what you’re working on.
3. Ensure that your changes do not cause any existing tests to fail.
4. Submit a pull request against the `main` branch.

## Code review process
1. PR will be reviewed by the maintainers and approved by workstream leads or their delegates (maintainers)
    * Grammatical errors, punctuation, white spaces? Need PR? 
3. Responses are due in 3 business days
   
The workstream maintainers are responsible for reviewing pull requests and issues in a timely manner (3 business days).

[Lazy consensus](https://openoffice.apache.org/docs/governance/lazyConsensus.html) is practiced for all projects and documents, including the main project repository and draft documents using other tools than Github.

Major changes on Github or to a WS document using any other official project platform should be accompanied by a post on the WS mailing list as appropriate. Author(s) of the proposal, Pull Requests, or issues, will give a time period of no less than seven (7) business days for comment and remain cognizant of popular observed world holidays.

## Branch naming and commit messages

### Branch naming

* `main` – main development branch, feature and release branches branched from it, changes only through the PR process.
* `feature` – feature/this-is-a-new-feature-branch
* `codebugfix` – codebugfix/name-of-the-bug
* `languagefix` - languagefix/fix-details
* `release` – release/1.0.0 - cut from main when ready

### Rebasing note

After completing work on a feature branch, rebase main before opening a PR. After PR is approved, rebase again to make sure changes from the latest main are picked up before merging the PR.

### Commit messages format:

In the commit message, always continue the sentence "This commit does ...".

 Examples of good commit messages:
"This commit renames examples folder in the root of the repo to reference-implementations"
"This commit bumps dependency packages versions to fix potential security issues".

## Signing the eCLA/iCLA

Anyone can do a pull request and commit. In order for your work to be merged, you will need to sign the iCLA (individual contributor agreement) if you are just contributing for yourself. If you are contributing on behalf of your company, you will also need to to sign the eCLA (entity contributor agreement). [Learn more about the CLAs here](https://www.oasis-open.org/open-projects/cla/).

The iCLA is administered by a bot which will comment on your PR and direct you to sign the iCLA if you haven’t previously done so. This happens automatically when people submit a pull request.


## Feedback

Questions or comments about this project's work may be composed as GitHub issues or comments or may be directed to the project's general email list at cosai-op@lists.oasis-open-projects.org. General questions about OASIS Open Projects may be directed to OASIS staff at [op-admin@lists.oasis-open-projects.org](mailto:op-admin@lists.oasis-open-projects.org).
