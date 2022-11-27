#!/usr/bin/python

import urllib3
import json
import os


def get_repo_list(org):

    try:
        apikey = os.environ["GH_API_KEY"]
        auth = "Bearer " + apikey
    except KeyError:
        print("GH_API_KEY environment variable not set")
        print("Please set the Github API via environment variable.")
        print("Eg. export GH_API_KEY=ghp_XXXXXXXXXXXXXXXXXXXXX")
        quit()

    http = urllib3.PoolManager()

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

    # flatten the json lists
    final_list = sum(all_repo_list, [])

    # keep active repos only
    non_archived = []

    for item in final_list:
        if item["archived"] is False:
            print(item["name"])
            non_archived.append(item)

    print(str(len(non_archived)))


# for item in range(len(json_resp)):
# print(json_resp[item]["name"])


# json_formatted = json.dumps(item, indent=2)
# print(type(json_formatted))

# final_formatted = json.dumps(item, indent=2)

# print(final_formatted)


def main():
    get_repo_list("procurify")


if __name__ == "__main__":
    main()
