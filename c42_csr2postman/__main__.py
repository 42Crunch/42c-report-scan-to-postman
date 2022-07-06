import json
import argparse

from c42_csr2postman.models import *
from c42_csr2postman.exceptions import *

def _write_postman_variable_(variable: str) -> str:
    return f"{{{{{variable}}}}}"

def csr2postman_v1(parsed_cli: argparse.Namespace):
    postman_output = parsed_cli.output_file
    csr_report_file = parsed_cli.CSR_REPORT_FILE

    try:
        with open(csr_report_file, "r") as f:
            csr_report_data = json.load(f)
    except IOError as e:
        raise Crunch42Exception(f"file '{csr_report_file}' not found")

    # Load report
    csr_report = CSRReportV1.from_csr_data(csr_report_data)

    #
    # User filters
    #
    only_priority = parsed_cli.only_priority

    #
    # Transform
    #

    # End-Points
    packages = []
    secrets = set()
    variables = {}

    for path, path_object in csr_report.paths.items():

        if only_priority and \
                path_object.total_unexpected > 0 \
                    and path_object.total_failure > 0:
                continue

        end_points = []

        if path_object.secrets:
            secrets.update(path_object.secrets)

        for k, v in path_object.variables.items():
            if k not in variables:
                variables[k] = v

        for issue in path_object.issues:

            url_parsed = urlparse(issue.url)

            # -------------------------------------------------------------------------
            # Setup variables
            # -------------------------------------------------------------------------
            if all(x in variables for x in ("host", "schema")):
                h_host = f"{_write_postman_variable_('host')}" \
                         f"://{_write_postman_variable_('schema')}"

                host = [h_host]
                raw = f"{h_host}{issue.url}"
            else:
                host = [f"{url_parsed.scheme}://{url_parsed.hostname}"]
                raw = issue.url,

            # -------------------------------------------------------------------------
            # Setup request content
            # -------------------------------------------------------------------------
            body = None
            if issue.body:
                body = PostmanBody(
                    mode="raw",
                    raw=issue.body
                )

            # -------------------------------------------------------------------------
            # Setup end-point name
            # -------------------------------------------------------------------------
            ep = PostmanEndPoint(
                name=issue.description,
                request=PostmanRequest(
                    method=path_object.method,
                    body=body,
                    url=PostmanUrl(
                        raw=raw,
                        host=host,
                        path=[issue.path]
                    ),
                    header=[
                        PostmanProperty(h, v)
                        for h, v in issue.headers.items()
                    ]
                )
            )

            end_points.append(ep)

        packages.append(
            PostmanPackage(
                name=path,
                items=end_points
            )
        )

    # -------------------------------------------------------------------------
    # Build postman configuration file
    # -------------------------------------------------------------------------
    file_secrets = [
        PostmanProperty(key=sec, value="")
        for sec in secrets
    ]

    file_variables = [
        PostmanProperty(key=k, value=v)
        for k, v in variables.items()
    ]

    postman = PostmanConfigFile(
        info=PostmanInfo(
            name=f"42Crunch Conformance Scan Report",
            description=f"Postman collection for test scan"
                        f" date '{csr_report.date}'",
        ),
        items=packages,
        variables=[*file_secrets, *file_variables]
    )

    # Dump
    with open(postman_output, "w") as f:
        json.dump(postman.raw_dict(), f)


def main():
    parser = argparse.ArgumentParser(
        description='42Crunch Conformance Scan Report 2 Postman convertor'
    )
    parser.add_argument('CSR_REPORT_FILE',
                        help="42Crunch Conformance Scan Report file")
    parser.add_argument('-d', '--debug',
                        default=False,
                        action="store_true",
                        help="enable debugging mode")
    parser.add_argument('-o', '--output-file',
                        default="42c_conformance_scan_report_postman.json",
                        help="output Postman file. Default: "
                             "'42c_conformance_scan_report_postman.json'")

    filters = parser.add_argument_group("filtering")
    filters.add_argument('-P', '--only-priority',
                         action="store_true",
                         default=False,
                         help="only choose priority issues")

    parsed_cli = parser.parse_args()

    try:
        csr2postman_v1(parsed_cli)
    except Crunch42Exception as e:
        print(f"[!] {e}")


if __name__ == '__main__':
    main()

