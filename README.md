# 42Crunch Conformance Scan Report to Postman converter

This Projects allows to convert a 42 Crunch Conformance Report into a Postman Collection.

## Requirements

The tool only works properly with scan reports created with version 1.14 or later (Dec 2021 Release).

## Install

### Cloning repository

```bash
$ git clone https://github.com/42c-presales/42c-report-scan-to-postman.git
$ cd 42c-report-scan-to-postman
$ pip install .
```

### Without cloning repository

```bash
$ pip install git+https://github.com/42c-presales/42c-report-scan-to-postman.git
```

## Usage 

### Getting help

```bash
$ 42c-csr -h
42Crunch Conformance Scan Report 2 Postman convertor

positional arguments:
  CSR_REPORT_FILE       42Crunch Conformance Scan Report file

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           enable debugging mode
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        output Postman file. Default: '42c_conformance_scan_report_postman.json'

filtering:
  -P, --only-priority   only choose priority issues
 
```

### Converting a Conformance Scan Report

```bash
$ 42c-csr examples/PhotoManager-conformance-scan-2021-10-27-21-11.json
$ ls
42c_conformance_scan_report_postman.json
```
    Now you can import '42c_conformance_scan_report_postman.json' in Postman
