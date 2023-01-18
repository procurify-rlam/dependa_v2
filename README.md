# Dependabot Scraper to Slack

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
* Python urllib3 module
* Python 3 - This was developed and tested with Python 3.10.  Likely to work
with Python 3.6 and above.  (f-strings used in print statements)


## Quick Start

1. Set the following environment variables:\
    a. GH_API_KEY - Github API key\
        eg: ```export GH_API_KEY=ghp_XXXXXXXXX```\
    b. GH_ORG - Github organization to query\
        eg: ```export GH_ORG=procurify```\
    c. SLACK_URL - slack url to the slack webhook\
        eg: ```export SLACK_URL="https://hooks.slack.com/services/XXX"```

2. ```pip install urlib3```

3. ```python3 dependabot_slack.py``` alternatively, if sending to a Slack
channel is not desired.\
```python3 dependabot_slack.py local``` will save all data to local disk.

* Output (CSV) files are written to the current folder.
* JSON files for each repo is saved to the current folder under ./output,
in the event manual review is needed.  Note, this data can also be viewed via Github,
within the reposistory, under the security tab, assuming appropriate permissions are granted.


## Notes

1. Optimization considerations:
    * Query Github via [GraphQL](https://github.blog/changelog/2022-06-29-dependabot-alerts-dependency-scope-filter-via-graphql-api/)
    * Vectorization via [NumPy](https://numpy.org/) or [Pandas](https://pandas.pydata.org/)
    (Pandas is built on top of NumPy)

2. Slack output (presentation) is limited.  Consequently, the output is less
   than ideal.

3. This script is maintained within a single file, for potential convenient
   deployment to AWS Lambda.  Although there are options to facilitate multiple
   files or utilize Lambda Layers, a single file deployment is most convenient.

4. Minimal use of external modules was intentional - again to minimize
   complexity for potential deployment to a AWS, as well as for local testing.


## TODO

1. Add Docstrings and type hints to the Repo Class, methods, and functions.


## References

[List organization repos](https://docs.github.com/en/rest/repos/repos#list-organization-repositories)\
[List dependabot alerts](https://docs.github.com/en/rest/dependabot/alerts#list-dependabot-alerts-for-a-repository)\
[Working with Dependabot](https://docs.github.com/en/code-security/dependabot/working-with-dependabot)\
[Github Dependabot Blog](https://github.blog/2020-06-01-keep-all-your-packages-up-to-date-with-dependabot/)


## License

Released under the [GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html)


## Contributing

Concerns/Questions, open an issue.  Improvements, please submit a pull request.
