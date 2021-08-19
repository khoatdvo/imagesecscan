#!/usr/bin/python3
import argparse
import json
import requests
import logging
import sys

logging.basicConfig(level=logging.INFO)
QUAY_API_URL = 'https://quay.io/api/v1'

class QuayImageSecscan:
    def __init__(self, apiUrl, imageInfo):
        self.apiUrl = apiUrl
        self.imageInfo = imageInfo
        self.imageId = ''
        self.manifest = ''
        self.vulnerabilities = []

    def getResult(self):
        return self.imageInfo

    def __getResonse(self, url):
        responseData = ''
        response = requests.get(url)
        if response.ok:
            responseData = response.json()
        else:
            logging.error("Failed to get response for {}".format(url))
            sys.exit()
        return responseData

    def secscan(self):
        requestUrl = "{}/repository/{}/{}/tag/".format(self.apiUrl, self.imageInfo['Organisation'], self.imageInfo['Repository'])
        responseData = self.__getResonse(requestUrl)
        for tag in responseData['tags']:
            if tag['name'] == self.imageInfo['Tag']:
                logging.info("Tag {} was found for repo {}/{}".format(tag['name'], self.imageInfo['Organisation'], self.imageInfo['Repository']))
                self.imageId = tag['image_id']
                self.manifest = tag['manifest_digest']
                self.imageInfo.update({
                    'Manifest': self.manifest
                })

                requestUrl = "{}/repository/{}/{}/manifest/{}/security?vulnerabilities=true".format(self.apiUrl, self.imageInfo['Organisation'], self.imageInfo['Repository'], self.manifest)
                responseData = self.__getResonse(requestUrl)
                for feature in responseData['data']['Layer']['Features']:
                    for vulnerability in feature['Vulnerabilities']:
                        vulnerability.update({
                            'PackageName': feature['Name']
                        })
                        self.vulnerabilities.append(vulnerability)
        
        self.imageInfo.update({
            'Vulnerabilities': self.vulnerabilities
        })

def main(args):
    with open(args.file) as input_file:
        imageList = json.load(input_file)
    result = []
    for image in imageList:
        quayImageSecscan = QuayImageSecscan(args.apiUrl, image)
        quayImageSecscan.secscan()
        result.append(quayImageSecscan.getResult())

    with open('output.json', 'w') as output:
        json.dump(result, output, indent=2, sort_keys=True)
    logging.debug("quayImageSecscan result is: {}".format(result))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--apiUrl', required=False, type=str, help='api url defaults to https://quay.io/api/v1', default='https://quay.io/api/v1')
    parser.add_argument('-f', '--file', required=True, type=str, help='input file')

    args = parser.parse_args()
    main(args)















# QUAY_API = 'https://quay.io/api/v1'

# input = open('second.input.json',)
# repoList = json.load(input)
# print(repoList)

# toReturn = []
# for repo in repoList:
#     url = "{}/repository/{}/{}/tag/".format(QUAY_API, repo['Organisation'], repo['Repository'])
#     res = requests.get(url)
#     data = res.json()
#     # print(data)
#     imageId = ''
#     manifest = ''
#     for tag in data['tags']:
#         if tag['name'] == repo['Tag']:
#             print(json.dumps(tag, indent=4, sort_keys=True))
#             imageId = tag['image_id']
#             manifest = tag['manifest_digest']

#     repo.update({
#         'Manifest': manifest
#     })

#     vulnerabilities = []
#     if imageId:
#         url = "{}/repository/{}/{}/manifest/{}/security?vulnerabilities=true".format(QUAY_API, repo['Organisation'], repo['Repository'], manifest)
#         res = requests.get(url)
#         data = res.json()
#         # print(json.dumps(data, indent=4, sort_keys=True))

#         for feature in data['data']['Layer']['Features']:
#             for vulnerability in feature['Vulnerabilities']:
#                 vulnerability.update({
#                     'PackageName': feature['Name']
#                 })
#                 vulnerabilities.append(vulnerability)
    
#     repo.update({
#         'Vulnerabilities': vulnerabilities
#     })
    
#     toReturn.append(repo)

# print(json.dumps(toReturn, indent=4, sort_keys=True))