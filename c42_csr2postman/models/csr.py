from __future__ import annotations

import re

from urllib.parse import urlparse
from typing import List, Union, Dict
from dataclasses import dataclass, field

from .interfaces import *

REGEX_BODY = re.compile(r'''(-d.*)([{\[])(.*)([\]}])''')
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

@dataclass
class Path:
    method: str
    issues: List[Issue] = field(default_factory=list)

    @classmethod
    def from_data(cls, method: str, json_data: dict) -> Path:
        o = cls(method=method)

        for issue in json_data.get("issues", []):
            content_type = CONTENT_TYPES[
                str(issue.get("requestContentType"))
            ]

            url = issue.get("url")
            path = urlparse(url).path
            curl_command = issue.get("curl")

            # Try to get Curl data: '-d' option
            body = None
            if " -d " in curl_command:

                # This regex only works for json payloads. We assume all
                # payloads are json
                if d := REGEX_BODY.search(curl_command):
                    _, prefix, content, sufix = d.groups()
                    body = f'{prefix}{content}{sufix}'

            # Try to get Curl headers: '-H' options
            headers = {}
            if found := REGEX_HEADERS.findall(curl_command):
                for match in found:
                    _, raw_header = match
                    header_key, header_value = raw_header.split(":")
                    headers[header_key.strip()] = header_value.strip()

            o.issues.append(
                Issue(
                    url=url,
                    path=path,
                    body=body,
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
