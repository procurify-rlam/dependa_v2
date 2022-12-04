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

        self.name = name

        (
            self.total_open,
            self.published_at,
            self.open_crit,
            self.open_high,
            self.open_med,
            self.open_low,
        ) = self.get_state_data("open", repo_dict)

        (
            self.total_fixed,
            self.fixed_at,
            self.fixed_crit,
            self.fixed_high,
            self.fixed_med,
            self.fixed_low,
        ) = self.get_state_data("fixed", repo_dict)

        (
            self.total_dismissed,
            self.dismissed_at,
            self.dismissed_crit,
            self.dismissed_high,
            self.dismissed_med,
            self.dismissed_low,
        ) = self.get_state_data("dismissed", repo_dict)

        (
            self.open_npm,
            self.open_pip,
            self.open_rubygems,
            self.open_nuget,
            self.open_maven,
            self.open_composer,
            self.open_rust,
            self.open_unknown,
        ) = self.get_eco_data("open", repo_dict)

        (
            self.fixed_npm,
            self.fixed_pip,
            self.fixed_rubygems,
            self.fixed_nuget,
            self.fixed_maven,
            self.fixed_composer,
            self.fixed_rust,
            self.fixed_unknown,
        ) = self.get_eco_data("fixed", repo_dict)

        (
            self.dismissed_npm,
            self.dismissed_pip,
            self.dismissed_rubygems,
            self.dismissed_nuget,
            self.dismissed_maven,
            self.dismissed_composer,
            self.dismissed_rust,
            self.dismissed_unknown,
        ) = self.get_eco_data("dismissed", repo_dict)

        self.priority = self.get_crit_high_sum()

    def get_language(self, item_dict, eco_dict):

        if item_dict["dependency"]["package"]["ecosystem"] == "npm":
            eco_dict["npm"] += 1
        elif item_dict["dependency"]["package"]["ecosystem"] == "pip":
            eco_dict["pip"] += 1
        elif item_dict["dependency"]["package"]["ecosystem"] == "rubygems":
            eco_dict["rubygems"] += 1
        elif item_dict["dependency"]["package"]["ecosystem"] == "nuget":
            eco_dict["nuget"] += 1
        elif item_dict["dependency"]["package"]["ecosystem"] == "maven":
            eco_dict["maven"] += 1
        elif item_dict["dependency"]["package"]["ecosystem"] == "composer":
            eco_dict["composer"] += 1
        elif item_dict["dependency"]["package"]["ecosystem"] == "rust":
            eco_dict["rust"] += 1
        else:
            eco_dict["unknown"] += 1

        return eco_dict

    def get_eco_data(self, state, repo_dict):

        get_eco_dict = {
            "npm": 0,
            "pip": 0,
            "rubygems": 0,
            "nuget": 0,
            "maven": 0,
            "composer": 0,
            "rust": 0,
            "unknown": 0,
        }

        for item in repo_dict:

            if item["state"] == state:
                if state == "open":
                    get_eco_dict = self.get_language(item, get_eco_dict)
                if state == "fixed":
                    get_eco_dict = self.get_language(item, get_eco_dict)
                if state == "dismissed":
                    get_eco_dict = self.get_language(item, get_eco_dict)

        return (
            get_eco_dict["npm"],
            get_eco_dict["pip"],
            get_eco_dict["rubygems"],
            get_eco_dict["nuget"],
            get_eco_dict["maven"],
            get_eco_dict["composer"],
            get_eco_dict["rust"],
            get_eco_dict["unknown"],
        )

    def get_state_data(self, state, repo_dict):

        total = 0
        date_list = []
        crit = 0
        high = 0
        med = 0
        low = 0
        date = ""

        for item in repo_dict:
            if item["state"] == state:
                total += 1

                if state == "open":
                    temp_pub_at_date = item["security_advisory"][
                        "published_at"
                    ]
                    date_list.append(
                        datetime.strptime(
                            temp_pub_at_date, "%Y-%m-%dT%H:%M:%SZ"
                        )
                    )
                    date = str(min(date_list))

                if state == "fixed":
                    temp_fixed_at_date = item["fixed_at"]
                    date_list.append(
                        datetime.strptime(
                            temp_fixed_at_date, "%Y-%m-%dT%H:%M:%SZ"
                        )
                    )
                    date = str(max(date_list))

                if state == "dismissed":
                    temp_dismissed_at_date = item["dismissed_at"]
                    date_list.append(
                        datetime.strptime(
                            temp_dismissed_at_date, "%Y-%m-%dT%H:%M:%SZ"
                        )
                    )
                    date = str(max(date_list))

                if item["security_advisory"]["severity"] == "critical":
                    crit += 1
                elif item["security_advisory"]["severity"] == "high":
                    high += 1
                elif item["security_advisory"]["severity"] == "medium":
                    med += 1
                else:
                    low += 1

        return (
            total,
            date,
            crit,
            high,
            med,
            low,
        )

    def get_crit_high_sum(self):
        return self.open_crit + self.open_high


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

        # if 30 or more items, the response will be paginated,
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
        "open critical": 0,
        "open high": 0,
        "open medium": 0,
        "open low": 0,
        "open npm": 0,
        "open pip": 0,
        "open rubygems": 0,
        "open nuget": 0,
        "open maven": 0,
        "open composer": 0,
        "open rust": 0,
        "open unknown": 0,
    }

    for data in range(len(parsed_data)):
        org_data["open critical"] += parsed_data[data]["open_crit"]
        org_data["open high"] += parsed_data[data]["open_high"]
        org_data["open medium"] += parsed_data[data]["open_med"]
        org_data["open low"] += parsed_data[data]["open_low"]
        org_data["open npm"] += parsed_data[data]["open_npm"]
        org_data["open pip"] += parsed_data[data]["open_pip"]
        org_data["open rubygems"] += parsed_data[data]["open_rubygems"]
        org_data["open nuget"] += parsed_data[data]["open_nuget"]
        org_data["open maven"] += parsed_data[data]["open_maven"]
        org_data["open composer"] += parsed_data[data]["open_composer"]
        org_data["open rust"] += parsed_data[data]["open_rust"]
        org_data["open unknown"] += parsed_data[data]["open_unknown"]

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


def main():

    parsed_data = []

    non_archived, archived = get_repo_list()
    # print(non_archived)

    (
        repos_no_vulns,
        repos_with_vulns,
        repos_disabled,
        vulns_json_data,
    ) = get_dependabot_alerts(non_archived)

    # create object for every repo with respective alert information
    for repo in range(len(vulns_json_data)):
        repo = Repo(repos_with_vulns[repo], vulns_json_data[repo])

        parsed_data.append(vars(repo))

    # sort rows based on "priority" column
    sorted_data = sorted(
        parsed_data, key=lambda d: d["priority"], reverse=True
    )

    write_csv_data(sorted_data)
    write_txt_data(sorted_data)

    org_data = get_org_data(
        repos_no_vulns, repos_with_vulns, repos_disabled, sorted_data
    )

    print()
    print(org_data)


# to write all json data locally
#    with open("parsed_data.json", "w", encoding="utf-8") as all_json_data_file:
#        json.dump(
#            vulns_json_data,
#            all_json_data_file,
#            indent=4,
#            sort_keys=False,
#            ensure_ascii=False,
#        )


if __name__ == "__main__":

    # keep auth and org values global in scope
    try:
        apikey = os.environ["GH_API_KEY"]
        auth = "Bearer " + apikey
    except KeyError:
        print("GH_API_KEY environment variable not set")
        print("Please set the Github API via environment variable.")
        print("Eg. export GH_API_KEY=ghp_XXXXXXXXXXXXXXXXXXXXX")
        sys.exit(1)

    if len(sys.argv) == 1:
        print("Please provide an organiztion to query.")
        print()
        print(f"python3 {sys.argv[0]} <name of org>")
        print(f"IE: python3 {sys.argv[0]} procurify")
        sys.exit(1)
    elif len(sys.argv) == 2:
        org = sys.argv[1]
    else:
        print("Too many arguments provided.")
        print("Exiting.")
        sys.exit(1)

    main()
