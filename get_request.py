#!/usr/bin/python

import urllib3
import json
import os
import sys
import re
import math


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

    print(non_archived[5])

    repos_no_vulns = []
    repos_with_vulns = []
    repos_disabled = []

    temp_vulns = []
    repo_vulns = []

    http = urllib3.PoolManager()
    # set args for http request
    page = 1
    url = (
        # f"https://api.github.com/repos/{org}/non_archived[0]/dependabot/alerts"
        f"https://api.github.com/repos/{org}/{non_archived[5]}/dependabot/alerts"
    )
    req_headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": auth,
    }

    # on initial request, no custom field headers added to the request
    # the intent, to determine the total length of the return via returned
    # link header
    resp = http.request("GET", url, headers=req_headers)
    json_resp_header = dict(resp.headers)

    print(json.dumps(json_resp_header, indent=2))
    print()

    # if response is paginated, find last page to query
    if "Link" in json_resp_header:
        pages_regex = re.findall(r"page=\d+", json_resp_header["Link"])
        lastpage_regex = re.findall(r"\d+", pages_regex[1])
        lastpage = int(lastpage_regex[0])
        # print(lastpage)

        # recalculate num of queries to make 100 items per request
        # default num of items returned is 30
        num_queries = int(math.ceil((lastpage * 30) / 100))
        # print(num_queries)
        for query in range(num_queries):
            req_fields = {"first": 100, "page": page}
            resp = http.request(
                "GET", url, fields=req_fields, headers=req_headers
            )
            json_resp = json.loads(resp.data.decode("utf-8"))
            temp_vulns.append(json_resp)

        # print(f"length of json_resp data: {len(json_resp)}")
    else:
        json_resp = json.loads(resp.data.decode("utf-8"))
        # if len(json_respon) == 0:

    # todo determine which repos have dependabot alerts/do not/disabled
    # return list of dictionaries for each

    temp_vulns.append(json_resp)
    print(temp_vulns)

    print()
    print()
    repo_vulns = sum(temp_vulns, [])

    print(str(len(repo_vulns)))

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
    non_archived, archived = get_repo_list()

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
