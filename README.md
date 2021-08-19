# Quay Image Security Scan
Small utility scirpt to get the security scan for Quay images

# How to use
It can be used as a standalone script or to be imported into other script as a class

Sample input format in json:
```json
[
  {
   "Organisation":"coreos",
   "Repository":"hyperkube",
   "Tag":"v1.10.4_coreos.0"
  },
  {
   "Organisation":"coreos",
   "Repository":"dnsmasq",
   "Tag":"v0.5.0"
  }
]
```
## Standalone mode
```bash
./quayImageSecscan.py --help
usage: quayImageSecscan.py [-h] [-a APIURL] -f FILE

optional arguments:
  -h, --help            show this help message and exit
  -a APIURL, --apiUrl APIURL
                        api url defaults to https://quay.io/api/v1
  -f FILE, --file FILE  input file
```
## Import to another class
```python
from quayImageSecscan import QuayImageSecscan

input = self.readInputFile('input.json')
with open(args.file) as input_file:
    imageList = json.load(input_file)
result = []
for image in imageList:
    quayImageSecscan = QuayImageSecscan(args.apiUrl, image)
    quayImageSecscan.secscan()
    result.append(quayImageSecscan.getResult())
```

## Output
The result will be dumped into `output.json` file in the same directory with the script
Sample output is:
```json
[
  {
    "Manifest": "sha256:ced8ba1345b8fef845ab256b7b4d0634423363721afe8f306c1a4bc4a75d9a0c",
    "Organisation": "coreos",
    "Repository": "hyperkube",
    "Tag": "v1.10.4_coreos.0",
    "Vulnerabilities": [
      {
        "Description": null,
        "FixedBy": null,
        "Link": "https://security-tracker.debian.org/tracker/CVE-2018-8086",
        "Metadata": null,
        "Name": "CVE-2018-8086",
        "NamespaceName": "debian:9",
        "PackageName": "glibc",
        "Severity": "Unknown"
      },
      {
        "Description": "The xdr_bytes and xdr_string functions in the GNU C Library (aka glibc or libc6) 2.25 mishandle failures of buffer deserialization, which allows remote attackers to cause a denial of service (virtual memory allocation, or memory consumption if an overcommit setting is not used) via a crafted UDP packet to port 111, a related issue to CVE-2017-8779.",
        "FixedBy": null,
        "Link": "https://security-tracker.debian.org/tracker/CVE-2017-8804",
        "Metadata": {
          "NVD": {
            "CVSSv2": {
              "Score": 7.8,
              "Vectors": "AV:N/AC:L/Au:N/C:N/I:N"
            }
          }
        },
        "Name": "CVE-2017-8804",
        "NamespaceName": "debian:9",
        "PackageName": "glibc",
        "Severity": "High"
      },
      ...
```