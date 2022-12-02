#!/usr/bin/python

import urllib3
import json
import os
import sys
import re
import math
import pprint


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
        # if item["archived"] is True:
        else:
            archived.append(item["name"])

    return non_archived, archived


def get_dependabot_alerts(non_archived):

    repos_no_vulns = []
    repos_with_vulns = []
    repos_disabled = []

    repo_vulns = []
    final_list = []

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
                print(f"json_resp: {type(json_resp)}")
                print(f"json_resp[0]: {type(json_resp[0])}")
                temp_vulns.append(json_resp)
                page += 1
            # flatten the list of lists, then add it as single item to a
            # list - each item in the final list representing
            # a single repo of dependabot information
            repo_vulns = sum(temp_vulns, [])
            final_list.append(repo_vulns)
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
                final_list.append(json_resp)

    print()
    print(f"repos_no_vulns: {repos_no_vulns}")
    print(f"repos_disabled: {repos_disabled}")
    print(f"repos_with_vulns: {repos_with_vulns}")

    print()
    # print(f"final_list: {final_list}")
    print(f"len final_list: {len(final_list)}")
    print(f"type final_list: {type(final_list)}")
    print()
    print(f"len final_list[0]: {len(final_list[0])}")
    print(f"type final_list[0]: {type(final_list[0])}")
    print()
    print(f"len final_list[1]: {len(final_list[1])}")
    print(f"type final_list[1]: {type(final_list[1])}")
    print()
    print(f"len final_list[2]: {len(final_list[2])}")
    print(f"type final_list[2]: {type(final_list[2])}")
    print()
    print(f"len final_list[3]: {len(final_list[3])}")
    print(f"type final_list[3]: {type(final_list[3])}")

    with open("all_data.json", "w", encoding="utf-8") as all_json_data_file:
        json.dump(
            final_list,
            all_json_data_file,
            indent=4,
            sort_keys=False,
            ensure_ascii=False,
        )


def main():

    # non_archived, archived = get_repo_list("procurify")
    # non_archived, archived = get_repo_list()
    # print(non_archived)

    get_dependabot_alerts(non_archived)


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
