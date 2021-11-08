# 42Crunch Conformance Scan Report to Postman converter

This Projects allows to convert a 42 Crunch Conformance Report into a Postman Collection.

## Install

### From GitHub

```bash
$ git clone https://github.com/42c-presales/42c-report-scan-to-postman.git
$ cd 42c-report-scan-to-postman
$ pip install .
```

### From Pypi

```bash
$ pip install 42c_csr2postman
```

## Usage 

### Getting help

```bash
$ 42c-csr -h
usage: 42c-csr [-h] [-d] [-o OUTPUT_FILE] CSR_REPORT_FILE

42Crunch Conformance Scan Report 2 Postman convertor

positional arguments:
  CSR_REPORT_FILE       42Crunch Conformance Scan Report file

optional arguments:
  -h, --help            show this help message and exit
  -d, --debug           enable debugging mode
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        output Postman file. Default: '42c_conformance_scan_report_postman.json' 
```

### Converting a Conformance Scan Report

```bash
$ 42c-csr examples/PhotoManager-conformance-scan-2021-10-27-21-11.json
$ ls
42c_conformance_scan_report_postman.json
```
    Now you can import '42c_conformance_scan_report_postman.json' in Postman

## TODO

[ ] Convert asterisk properties into variables
[ ] Add responses to the Postman collection
