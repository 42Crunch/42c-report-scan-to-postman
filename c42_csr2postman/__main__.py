import json
import argparse

from c42_csr2postman.models import *
from c42_csr2postman.exceptions import *

def csr2postman(parsed_cli: argparse.Namespace):
    postman_output = parsed_cli.output_file
    csr_report_file = parsed_cli.CSR_REPORT_FILE

    try:
        with open(csr_report_file, "r") as f:
            csr_report_data = json.load(f)
    except IOError as e:
        raise Crunch42Exception(f"file '{csr_report_file}' not found")

    # Load report
    csr_report = CSRReport.from_csr_data(csr_report_data)

    #
    # Transform
    #

    # End-Points
    packages = []
    for path, path_object in csr_report.paths.items():

        end_points = []

        for issue in path_object.issues:

            url_parsed = urlparse(issue.url)

            ep = PostmanEndPoint(
                name=issue.path,
                request=PostmanRequest(
                    method=path_object.method,
                    url=PostmanUrl(
                        raw=issue.url,
                        host=[f"{url_parsed.scheme}://{url_parsed.hostname}"],
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

    postman = PostmanConfigFile(
        info=PostmanInfo(
            name=f"42Crunch Conformance Scan Report",
            description=f"Postman collection for test scan"
                        f" date '{csr_report.date}'",
        ),
        items=packages
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
                        help="output Postman file. Default: '42c_conformance_scan_report_postman.json'")
    parsed_cli = parser.parse_args()

    try:
        csr2postman(parsed_cli)
    except Crunch42Exception as e:
        print(f"[!] {e}")


if __name__ == '__main__':
    main()

