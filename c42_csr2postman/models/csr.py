from __future__ import annotations

import re

from typing import List, Dict
from urllib.parse import urlparse
from dataclasses import dataclass, field

REGEX_HEADERS = re.compile(r'''(\-H[\s]*\')([\w\-\_\d\:\s\*\/\\\.]+)''')

CONTENT_TYPES = {
    '0': '',
    '1': 'application/json; charset=utf-8',
    '2': 'text/html; charset=utf-8',
    '3': 'application/x-www-form-urlencoded',
    '4': 'application/json',
    '5': 'application/random+content+type',
    '6': 'text/html'
}


@dataclass
class Issue:
    url: str
    path: str
    body: str
    content_type: str
    headers: dict
    description: str
    priority: int

@dataclass
class Path:
    method: str
    total_failure: int = 0
    total_unexpected: int = 0
    total_expected: int = 0
    secrets: List[str] = field(default_factory=list)
    issues: List[Issue] = field(default_factory=list)
    variables: Dict[str] = field(default_factory=dict)

    @classmethod
    def from_data(cls,
                  method: str,
                  json_data: dict,
                  injection_keys: list,
                  response_keys: list) -> Path:

        def clean_field(secret: str, replace_by: str = "") -> str:
            return secret.replace("-", replace_by).replace("_", replace_by)

        o = cls(method=method)

        objects = 1
        o.total_expected = json_data.get("totalExpected")
        o.total_unexpected = json_data.get("totalUnexpected")
        o.total_failure = json_data.get("totalFailure")

        issues = json_data.get("issues", [])

        for issue in issues:
            content_type = CONTENT_TYPES[
                str(issue.get("requestContentType"))
            ]

            prio_issue = 0
            if (o.total_unexpected > 0 or o.total_failure > 0 ):
                #Check current issue response_key as one or multiple issues are higher priority
                responseKey_array = issue.get("apiResponseAnalysis", [])
                for tmp_response_object in responseKey_array:
                    tmp_responseKey_label = response_keys[tmp_response_object.get("responseKey")]
                    if ("response-error-unexpected-scan" in tmp_responseKey_label ):
                        prio_issue = 1

            url = issue.get("url")
            parsed_url = urlparse(url)

            #
            # Extract domain and schema as a variable
            #
            o.variables["schema"] = parsed_url.scheme
            o.variables["host"] = parsed_url.netloc

            path = parsed_url.path
            curl_command = issue.get("curl")

            # Try to get Curl data: '-d' option
            body = None
            if " -d " in curl_command:
                body_starts = curl_command.find("-d") + 3
                body_end = curl_command.find("-H")

                body = curl_command[body_starts:body_end].strip()

                if body[0] in ("'", '"'):
                    body = body[1:]

                if body[-1] in ("'", '"'):
                    body = body[:-1]

            # Try to get Curl headers: '-H' options
            headers = {}
            if found := REGEX_HEADERS.findall(curl_command):
                for match in found:
                    _, raw_header = match
                    header_key, header_value = raw_header.split(":")

                    header_key = header_key.strip()
                    header_value = header_value.strip()

                    # Try to find passwords, access tokens, etc
                    if len(header_value) == header_value.count("*"):
                        # This is a secret!
                        secret_name = clean_field(header_key)

                        o.secrets.append(secret_name)

                        value = f"{{{{{secret_name}}}}}"
                    else:
                        value = header_value.strip()

                    headers[header_key.strip()] = value

            if q := parsed_url.query:
                new_url = f"{path}?{q}"
            else:
                new_url = path


            description = ""
            if desc_index := issue.get("injectionDescriptionParams", []):
                tmp = desc_index[0]

                if tmp == method:
                    description = f"Testing '{method}' HTTP method"

                elif any(x in tmp for x in ("/", "+")):
                    description = f"Testing '{tmp}' values"

            if not description:
                if key := issue.get("injectionKey", None):
                    k = injection_keys[key]
                    description = clean_field(k, " ").capitalize()

            if not description:
                description = f"Testing dangerous values ({objects})"
                objects += 1

            o.issues.append(
                Issue(
                    url=new_url,
                    path=path,
                    body=body,
                    description=description,
                    content_type=content_type,
                    headers=headers,
                    priority=prio_issue
                )
            )

        return o

@dataclass
class CSRReport:
    host: str
    date: str
    aid: str
    paths: Dict[str, Path] = field(default_factory=dict)

    @classmethod
    def from_csr_data(cls, json_data: dict) -> CSRReport:
        data = json_data.get("data")

        o = cls(
            host=data.get("host"),
            date=json_data.get("date"),
            aid=json_data.get("aid")
        )

        injection_keys = json_data.get(
            "data", {}
        ).get("index", {}).get("injectionKeys")

        response_keys = json_data.get(
            "data", {}
        ).get("index", {}).get("responseKeys")

        for path, path_data in data.get("paths").items():
            
            for method, method_data in path_data.items():
                path_obj = Path.from_data(method, method_data, injection_keys, response_keys)
                issue_id = path + "_"+ method
                if path_obj.issues:
                    o.paths[issue_id] = path_obj

        return o
