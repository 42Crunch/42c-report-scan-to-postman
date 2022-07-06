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
class IssueV1:
    url: str
    path: str
    body: str
    content_type: str
    headers: dict
    description: str

@dataclass
class PathV1:
    method: str
    total_failure: int = 0
    total_unexpected: int = 0
    secrets: List[str] = field(default_factory=list)
    issues: List[IssueV1] = field(default_factory=list)
    variables: Dict[str] = field(default_factory=dict)

    @classmethod
    def from_data(cls,
                  method: str,
                  json_data: dict,
                  injection_keys: list) -> PathV1:

        def clean_field(secret: str, replace_by: str = "") -> str:
            return secret.replace("-", replace_by).replace("_", replace_by)

        o = cls(method=method)

        objects = 1

        issues = json_data.get("issues", [])

        o.total_failure = json_data.get("totalFailure", len(issues))
        o.total_unexpected = json_data.get("totalUnexpected", 0)

        for issue in issues:
            try:
                content_type = CONTENT_TYPES[
                    str(issue.get("requestContentType"))
                ]
            except KeyError:
                content_type = ""

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
                IssueV1(
                    url=new_url,
                    path=path,
                    body=body,
                    description=description,
                    content_type=content_type,
                    headers=headers
                )
            )

        return o

@dataclass
class CSRReportV1:
    host: str
    date: str
    paths: Dict[str, PathV1] = field(default_factory=dict)

    @classmethod
    def from_csr_data(cls, json_data: dict) -> CSRReportV1:
        data = json_data.get("data")

        o = cls(
            host=data.get("host"),
            date=json_data.get("date")
        )

        injection_keys = json_data.get(
            "data", {}
        ).get("index", {}).get("injectionKeys")

        for path, path_data in data.get("paths").items():

            for method, method_data in path_data.items():
                path_obj = PathV1.from_data(method, method_data, injection_keys)

                if path_obj.issues:
                    o.paths[path] = path_obj

        return o
