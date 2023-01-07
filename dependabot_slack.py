#!/usr/bin/python

import urllib3
import json
import os
import sys
import re
import pprint
import csv
from datetime import datetime


class Repo:
    def __init__(self, name, repo_dict):

        (
            state_open,
            state_fixed,
            state_dismissed,
        ) = self.get_state_data(repo_dict)

        combined_data = {
            **state_open,
            **state_fixed,
            **state_dismissed,
        }

        # returned the parsed data as a single large dictionary
        self.parsed_data = {"Name": name}
        self.parsed_data.update(combined_data)

    def get_state_data(self, repo_dict):

        # template dictionary keys; allows reuse of nested parse_data function
        state_template = {
            "Total": 0,
            "Crit": 0,
            "High": 0,
            "Med": 0,
            "Low": 0,
            "Date": "",
            "Npm": 0,
            "Pip": 0,
            "Rubygems": 0,
            "Nuget": 0,
            "Maven": 0,
            "Composer": 0,
            "Rust": 0,
            "Unknown": 0,
        }
        state_open = dict(state_template)
        date_list_open = []

        state_fixed = dict(state_template)
        date_list_fixed = []

        state_dismissed = dict(state_template)
        date_list_dismissed = []

        def parse_data(item_dict, parsed_dict):

            parsed_dict["Total"] += 1

            if item_dict["security_advisory"]["severity"] == "critical":
                parsed_dict["Crit"] += 1
            elif item_dict["security_advisory"]["severity"] == "high":
                parsed_dict["High"] += 1
            elif item_dict["security_advisory"]["severity"] == "medium":
                parsed_dict["Med"] += 1
            else:
                parsed_dict["Low"] += 1

            if item_dict["dependency"]["package"]["ecosystem"] == "npm":
                parsed_dict["Npm"] += 1
            elif item_dict["dependency"]["package"]["ecosystem"] == "pip":
                parsed_dict["Pip"] += 1
            elif item_dict["dependency"]["package"]["ecosystem"] == "rubygems":
                parsed_dict["Rubygems"] += 1
            elif item_dict["dependency"]["package"]["ecosystem"] == "nuget":
                parsed_dict["Nuget"] += 1
            elif item_dict["dependency"]["package"]["ecosystem"] == "maven":
                parsed_dict["Maven"] += 1
            elif item_dict["dependency"]["package"]["ecosystem"] == "composer":
                parsed_dict["Composer"] += 1
            elif item_dict["dependency"]["package"]["ecosystem"] == "rust":
                parsed_dict["Rust"] += 1
            else:
                parsed_dict["Unknown"] += 1

            return parsed_dict

        for item in repo_dict:
            if item["state"] == "open":
                state_open = parse_data(item, state_open)

                # keep only first reported open alert date
                temp_pub_at_date = item["security_advisory"]["published_at"]
                date_list_open.append(
                    datetime.strptime(temp_pub_at_date, "%Y-%m-%dT%H:%M:%SZ")
                )
                state_open["Date"] = str(min(date_list_open))

            elif item["state"] == "fixed":
                state_fixed = parse_data(item, state_fixed)

                # keep only most recent fixed alert date
                temp_fixed_at_date = item["fixed_at"]
                date_list_fixed.append(
                    datetime.strptime(temp_fixed_at_date, "%Y-%m-%dT%H:%M:%SZ")
                )
                state_fixed["Date"] = str(max(date_list_fixed))

            elif item["state"] == "dismissed":
                state_dismissed = parse_data(item, state_dismissed)

                # keep only most recent dismissed alert date
                temp_dismissed_at_date = item["dismissed_at"]
                date_list_dismissed.append(
                    datetime.strptime(
                        temp_dismissed_at_date, "%Y-%m-%dT%H:%M:%SZ"
                    )
                )
                state_dismissed["Date"] = str(max(date_list_dismissed))

        # amend the dictionaries keys to reflect the state data
        state_open = {
            f"Open {key}": value for key, value in state_open.items()
        }
        state_fixed = {
            f"Fixed {key}": value for key, value in state_fixed.items()
        }
        state_dismissed = {
            f"Dismissed {key}": value for key, value in state_dismissed.items()
        }

        # set a priority level for remediation for open alerts
        priority = state_open["Open Crit"] + state_open["Open High"]
        state_open["Priority"] = priority

        return state_open, state_fixed, state_dismissed


def get_repo_list():

    http = urllib3.PoolManager()
    # set args for http request
    all_repo_list = []
    page = 1
    url = f"https://api.github.com/orgs/{org}/repos"
    req_fields = {"per_page": 100, "page": page}
    req_headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": auth,
    }
    resp = http.request("GET", url, fields=req_fields, headers=req_headers)
    json_resp = json.loads(resp.data.decode("utf-8"))
    all_repo_list.append(json_resp)

    if len(json_resp) == 100:
        while len(json_resp) == 100:
            page += 1
            req_fields = {"per_page": 100, "page": page}
            resp = http.request(
                "GET", url, fields=req_fields, headers=req_headers
            )
            json_resp = json.loads(resp.data.decode("utf-8"))
            all_repo_list.append(json_resp)

    # flatten the list of json lists to a single list
    final_list = sum(all_repo_list, [])

    # create separate lists for archived and non-archived repos
    archived = []
    non_archived = []
    for item in final_list:
        if item["archived"] is False:
            non_archived.append(item["name"])
        else:
            archived.append(item["name"])

    return non_archived, archived


def get_dependabot_alerts(non_archived):

    repos_no_vulns = []
    repos_with_vulns = []
    repos_disabled = []
    repo_vulns = []
    vulns_json_data = []

    http = urllib3.PoolManager()
    # set args for http request
    req_headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": auth,
    }

    for repo_name in non_archived:
        page = 1
        temp_vulns = []

        print(f"Getting Dependabot alert info for: {repo_name}")

        url = (
            f"https://api.github.com/repos/{org}/{repo_name}/dependabot/alerts"
        )
        # custom field headers are not added to the initial request
        # this determines the total number of pages in the response via the
        # link header; link header only present if response requires pagination
        resp = http.request("GET", url, headers=req_headers)
        json_resp_header = dict(resp.headers)

        # if 30 or more items, response will be paginated,
        # find last page to query
        if "Link" in json_resp_header:
            pages_regex = re.findall(r"page=\d+", json_resp_header["Link"])
            lastpage_regex = re.findall(r"\d+", pages_regex[1])
            lastpage = int(lastpage_regex[0])
            repos_with_vulns.append(repo_name)

            for query in range(lastpage):
                req_fields = {"page": page}
                resp = http.request(
                    "GET", url, fields=req_fields, headers=req_headers
                )
                json_resp = json.loads(resp.data.decode("utf-8"))
                temp_vulns.append(json_resp)
                page += 1
            # flatten the list of lists, then add it as single list to a
            # list - each item in the final list representing
            # a single repo of dependabot information
            repo_vulns = sum(temp_vulns, [])
            vulns_json_data.append(repo_vulns)

        else:
            json_resp = json.loads(resp.data.decode("utf-8"))
            if len(json_resp) == 0:
                # no dependabot alerts associated with the repo
                repos_no_vulns.append(repo_name)
            elif "message" in json_resp:
                # dependabot alerts disabled for the repo
                repos_disabled.append(repo_name)
            else:
                # less than 30 dependabot alerts associated with the repo
                repos_with_vulns.append(repo_name)
                vulns_json_data.append(json_resp)

    return repos_no_vulns, repos_with_vulns, repos_disabled, vulns_json_data


def get_org_data(
    repos_no_vulns, repos_with_vulns, repos_disabled, parsed_data
):

    num_no_vulns = len(repos_no_vulns)
    num_with_vulns = len(repos_with_vulns)
    num_disabled = len(repos_disabled)
    total_repos = num_no_vulns + num_with_vulns + num_disabled

    org_data = {
        "Total Number of Repos": total_repos,
        "Repos with alerts": num_with_vulns,
        "Repos without alerts": num_no_vulns,
        "Repos disabled alerts": num_disabled,
        "Open Crit": 0,
        "Open High": 0,
        "Open Med": 0,
        "Open Low": 0,
        "Open Npm": 0,
        "Open Pip": 0,
        "Open Rubygems": 0,
        "Open Nuget": 0,
        "Open Maven": 0,
        "Open Composer": 0,
        "Open Rust": 0,
        "Open Unknown": 0,
    }

    for data in range(len(parsed_data)):
        org_data["Open Crit"] += parsed_data[data]["Open Crit"]
        org_data["Open High"] += parsed_data[data]["Open High"]
        org_data["Open Med"] += parsed_data[data]["Open Med"]
        org_data["Open Low"] += parsed_data[data]["Open Low"]
        org_data["Open Npm"] += parsed_data[data]["Open Npm"]
        org_data["Open Pip"] += parsed_data[data]["Open Pip"]
        org_data["Open Rubygems"] += parsed_data[data]["Open Rubygems"]
        org_data["Open Nuget"] += parsed_data[data]["Open Nuget"]
        org_data["Open Maven"] += parsed_data[data]["Open Maven"]
        org_data["Open Composer"] += parsed_data[data]["Open Composer"]
        org_data["Open Rust"] += parsed_data[data]["Open Rust"]
        org_data["Open Unknown"] += parsed_data[data]["Open Unknown"]

    return org_data


def write_csv_data(sorted_data):

    repo_header = sorted_data[0].keys()
    parsed_data_csv = "parsed_data.csv"

    with open(parsed_data_csv, "w") as parsed_data_file:
        writer = csv.DictWriter(parsed_data_file, fieldnames=repo_header)
        writer.writeheader()
        writer.writerows(sorted_data)

    print()
    print(f"CSV of all dependabot repos written to {parsed_data_csv}")


def write_txt_data(sorted_data):

    parsed_data_txt = "parsed_data.txt"

    with open(parsed_data_txt, "w") as parsed_data_file:
        pp = pprint.PrettyPrinter(
            depth=4, sort_dicts=False, stream=parsed_data_file
        )
        pp.pprint(sorted_data)

    print()
    print(f"Text file of all dependabot repos written to {parsed_data_txt}")


def add_text_data(info, data_type):
    """Create code block to send to slack channel"""

    if data_type == "repo_data":
        header = f'{"Repo Name".ljust(7)}{info["Name"].rjust(40)}\n'
        header += (
            f'{"Total Open".ljust(7)}{str(info["Open Total"]).rjust(30)}\n'
        )
    elif data_type == "org_data":
        header = f'{"Dependabot Alerts for all Active Repos".ljust(7)}\n'

    repo_text = f"```"
    repo_text += header
    repo_text += f'{"Critical".ljust(7)}{str(info["Open Crit"]).rjust(33)}\n'
    repo_text += f'{"High".ljust(7)}{str(info["Open High"]).rjust(33)}\n'
    repo_text += f'{"Medium".ljust(7)}{str(info["Open Med"]).rjust(33)}\n'
    repo_text += f'{"Low".ljust(7)}{str(info["Open Low"]).rjust(33)}\n'
    repo_text += f"```"
    repo_text += f"\n"

    return repo_text


def send_to_slack(text):

    http = urllib3.PoolManager()
    repo_data = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "Top Five Repos - Dependabot Alerts Severity",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": text,
                },
            },
            {"type": "divider"},
        ]
    }

    r = http.request(
        "POST",
        slack_webhook,
        body=json.dumps(repo_data),
        headers={"Content-type": "application/json"},
    )
    # print(r.status)


def main():

    parsed_data = []
    non_archived, archived = get_repo_list()

    (
        repos_no_vulns,
        repos_with_vulns,
        repos_disabled,
        vulns_json_data,
    ) = get_dependabot_alerts(non_archived)

    # create object for every repo with respective alert information
    for repo in range(len(vulns_json_data)):
        repo = Repo(repos_with_vulns[repo], vulns_json_data[repo])
        parsed_data.append(repo.parsed_data)

    # sort rows based on "priority" column
    sorted_data = sorted(
        parsed_data, key=lambda d: d["Priority"], reverse=True
    )

    org_data = get_org_data(
        repos_no_vulns, repos_with_vulns, repos_disabled, sorted_data
    )

    if forward_to_slack:
        if len(sorted_data) >= 5:
            NUM_REPOS_REPORT = 5
        else:
            NUM_REPOS_REPORT = len(sorted_data)

        text = ""

        data_type = "repo_data"
        for number in range(NUM_REPOS_REPORT):
            text += add_text_data(sorted_data[number], data_type)
        send_to_slack(text)

        data_type = "org_data"
        text += add_text_data(org_data, data_type)
        send_to_slack(text)
    else:
        data_type = "repo_data"
        write_csv_data(sorted_data)
        write_txt_data(sorted_data)
        data_type = "org_data"
        # write_csv_data(org_data)

    print()
    print(org_data)


if __name__ == "__main__":

    # forward_to_slack, auth, org, slack_webhook global vars
    forward_to_slack = False

    try:
        apikey = os.environ["GH_API_KEY"]
        auth = "Bearer " + apikey
    except KeyError:
        print("GH_API_KEY environment variable not set")
        print("Please set the Github API via environment variable.")
        print("Eg: export GH_API_KEY=ghp_XXXXXXXXX")
        sys.exit(1)

    if len(sys.argv) == 1:
        print("Please provide an organization name to query.")
        print()
        print(f"python3 {sys.argv[0]} <name of org>")
        print(f"Eg: python3 {sys.argv[0]} procurify")
        sys.exit(1)
    elif len(sys.argv) == 2:
        org = sys.argv[1]
    elif (len(sys.argv) == 3) and (sys.argv[2] == "slack"):
        org = sys.argv[1]
        try:
            slack_webhook = os.environ["SLACK_URL"]
            forward_to_slack = True
        except KeyError:
            print("SLACK_URL environment variable not set")
            print("Please set the SLACK_URL via environment variable.")
            print("Eg: export SLACK_URL=https://hooks.slack.com/services/XXX")
            sys.exit(1)

    main()
