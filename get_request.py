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

    temp_vulns = []
    repo_vulns = []

    http = urllib3.PoolManager()
    # set args for http request
    page = 1
    req_headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": auth,
    }

    for repo_name in non_archived:

        print(f"Getting Dependabot alert info for: {repo_name}")

        url = (
            f"https://api.github.com/repos/{org}/{repo_name}/dependabot/alerts"
        )
        # on initial request, no custom field headers are added to the request
        # this is to determine the total number of items in the response via
        # the link header
        resp = http.request("GET", url, headers=req_headers)
        json_resp_header = dict(resp.headers)

        # if response is paginated, find last page to query
        if "Link" in json_resp_header:
            pages_regex = re.findall(r"page=\d+", json_resp_header["Link"])
            lastpage_regex = re.findall(r"\d+", pages_regex[1])
            lastpage = int(lastpage_regex[0])
            repos_with_vulns.append(repo_name)
            print(repo_name)

            for query in range(lastpage):
                req_fields = {"page": page}
                resp = http.request(
                    "GET", url, fields=req_fields, headers=req_headers
                )
                json_resp = json.loads(resp.data.decode("utf-8"))
                print(f"json_resp: {type(json_resp)}")
                # print(f"json_resp[0]: {type(json_resp[0])}")
                temp_vulns.append(json_resp)
                page += 1
        else:
            json_resp = json.loads(resp.data.decode("utf-8"))
            if len(json_resp) == 0:
                repos_no_vulns.append(repo_name)
            elif "message" in json_resp:
                repos_disabled.append(repo_name)
            else:
                repos_with_vulns.append(repo_name)
        # todo determine which repos have dependabot alerts/do not/disabled
        # return list of dictionaries for each

    print()
    print(f"repos_no_vulns: {repos_no_vulns}")
    print(f"repos_disabled: {repos_disabled}")
    print(f"repos_with_vulns: {repos_with_vulns}")
    print()
    print()
    print()
    # print(f"repos_with_vulns: {repos_with_vulns[2]}")
    # print(f"type (repos_with_vulns): {type(repos_with_vulns[0][0])}")
    print(f"len (temp_vulns): {str(len(temp_vulns))}")
    print(f"type (temp_vulns): {type(temp_vulns)}")
    print(f"type (temp_vulns[0]): {type(temp_vulns[0])}")
    print()

    with open("all_data.json", "w", encoding="utf-8") as all_json_data_file:
        json.dump(
            temp_vulns,
            all_json_data_file,
            indent=4,
            sort_keys=False,
            ensure_ascii=False,
        )

    # print(type(repo_vulns[0]))
    # print(repo_vulns[0])

    # for item in repo_vulns:
    # print(item["state"])

    # final_list = sum(all_repo_list, [])

    # temp_vulns.append(json_resp)

    # print(len(json.dumps(json_resp_header["Link"])))
    # print(json.dumps(json_resp, indent=2))


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
