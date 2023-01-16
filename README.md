# Dependabot Scraper to Slack `

Dependabot Information scraper for Github


## Introduction

This script scrapes and parses information regarding
dependabot alerts for Github repositories belonging to an organization.

Primary data points parsed are open, fixed, dismissed vulnerabilities, and
ecosystem (programming language) type of vulnerability.


## Prerequisites

* Bash or ZSH Shell
* A Github token with _security_events_ scope to read private repositories is
required.
* Python 3 - This was developed and tested with Python 3.10.  Likely to work
with Python 3.6 and above.  (f-strings used in print statements)


## Quick Start

1. Set the following environment variables:
    a. GH_API_KEY - Github API key
        eg: export GH_API_KEY=ghp_XXXXXXXXX
    b. GH_ORG - Github organization to query
        eg: export GH_ORG=procurify
    c. SLACK_URL - slack url to the slack webhook
        eg: export SLACK_URL=https://hooks.slack.com/services/XXX"

2. ```python3 dependabot_slack.py``` alternatively, if sending to a Slack
channel is not desired. ```python3 dependabot_slack.py local``` will save all
data to local disk.  Data will be written to current folder; observer STDOUT
for filenames.


****

4. Output (CSV) files are written to the current folder.
    * JSON files for each repo is saved to ./output folder, in the event manual
review is needed.  This data can also be viewed via Github, assuming
appropriate permissions are granted.


## Notes

1. Jq is unceessary for either the bash or the python script.  Jq is used to
provide convenient human readable review of the json files, if needed.
(Otherwise all the json returns (files) are in a single line.)

2. Optimization considerations:
    * Query Github via [GraphQL](https://github.blog/changelog/2022-06-29-dependabot-alerts-dependency-scope-filter-via-graphql-api/)
    * Vectorization via [NumPy](https://numpy.org/) or [Pandas](https://pandas.pydata.org/)
    (Pandas is built on top of NumPy)


## TODO

1. Remove dependency on gh cli command and almalgamate both scripts to
a single Python script.  (potentially have this run on as an AWS Lambda and
executed via scheduled EventBridge event and forward to a platform such as
Slack)
2. Provide method to name input / output file and folder names via command line
   paramaeters.
3. Optimize code (reduce some repetitive code).
4. Generate graphics with Plotly or alternative graphing module with Python.(?)
5. Add Docstrings and type hints to the Repo Class, methods, and functions.


## References

[Github CLI login](https://cli.github.com/manual/gh_auth_login)\
[List oranization repos](https://docs.github.com/en/rest/repos/repos#list-organization-repositories)\
[List dependabot alerts](https://docs.github.com/en/rest/dependabot/alerts#list-dependabot-alerts-for-a-repository)\
[Working with Dependabot](https://docs.github.com/en/code-security/dependabot/working-with-dependabot)\
[Github Dependabot Blog](https://github.blog/2020-06-01-keep-all-your-packages-up-to-date-with-dependabot/)


## License

Released under the [GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html)


## Contributing

Concerns/Questions, open an issue.  Improvements, please submit a pull request.
