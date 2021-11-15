from __future__ import annotations

import re

from urllib.parse import urlparse
from typing import List, Union, Dict
from dataclasses import dataclass, field

from .interfaces import *

REGEX_HEADERS = re.compile(r'''(\-H[\s]*\')([\w\-\_\d\:\s\*\/\\\.]+)''')

CONTENT_TYPES = {
    '0': '',
    '3': 'application/x-www-form-urlencoded',
    '4': 'application/json',
    '5': 'application/random+content+type'
}


@dataclass
class Issue:
    url: str
    path: str
    body: str
    content_type: str
    headers: dict
    description: str

@dataclass
class Path:
    method: str
    secrets: List[str] = field(default_factory=list)
    issues: List[Issue] = field(default_factory=list)
    variables: Dict[str] = field(default_factory=dict)

    @classmethod
    def from_data(cls, method: str, json_data: dict) -> Path:

        def clean_secret(secret: str) -> str:
            return secret.replace("-", "").replace("_", "")

        o = cls(method=method)

        objects = 1

        for issue in json_data.get("issues", []):
            content_type = CONTENT_TYPES[
                str(issue.get("requestContentType"))
            ]

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
                        secret_name = clean_secret(header_key)

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
                description = desc_index[0]

                if description == method:
                    description = f"Testing '{method}' HTTP method"

                elif any(x in description for x in ("/", "+")):
                    description = f"Testing '{description}' values"

                else:
                    description = f"Testing dangerous values ({objects})"
                    objects += 1
            else:
                description = f"Testing dangerous values ({objects})"
                objects += 1

            o.issues.append(
                Issue(
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
class CSRReport:
    host: str
    date: str
    paths: Dict[str, Path] = field(default_factory=dict)

    @classmethod
    def from_csr_data(cls, json_data: dict) -> CSRReport:
        data = json_data.get("data")

        o = cls(
            host=data.get("host"),
            date=json_data.get("date")
        )

        for path, path_data in data.get("paths").items():

            for method, method_data in path_data.items():
                path_obj = Path.from_data(method, method_data)

                if path_obj.issues:
                    o.paths[path] = path_obj

        return o
