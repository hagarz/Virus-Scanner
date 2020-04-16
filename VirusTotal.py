__author__ = 'Hagar Zemach'


import requests, json, time


def get_key():
    """gets api key from file"""
    with open("APIKey.txt", 'r') as file:
            key = file.read()
    file.close()
    return key


class VirusTotal(object):
    """
    checks suspicious file in VirusTotal and fetch the VirusTotal scan results
        # VirusTotal API is limited 4 requests in 1 minute time frame
        # Request rate	4 requests/minute
        # Daily quota	1,000 requests/day
        # Monthly quota	30,000 requests/month
    """
    def __init__(self):
        self.apiKey = get_key()
        self.base_url = 'https://www.virustotal.com/vtapi/v2/'
        self.files_id_dic = {}
        self.scan_id_list = []
        self.result = {}
        self.infected = {}

    def virustotal_manager(self, file_list):
        self.scan(file_list)  # send files for scanning
        print(f"{len(self.scan_id_list)} files were scanned\n fetching reports...")
        self.get_report()  # fetching reports

        for sid in self.result:
            if int(self.result[sid]['positives']) > 0:
                self.infected[self.files_id_dic[sid]] = \
                    [str(round(100*(self.result[sid]['positives'] / self.result[sid]['total']),2))+'%',
                     self.result[sid]['scanners']]

        print("\n--=SUMMARY=--")
        print(f"{len(file_list)} files were sent for scanning")
        print(f"{len(self.scan_id_list)} files were scanned \n {len(self.infected)} infected files were found:")
        for name in self.infected:
            print(f"malware detected in {name} with {self.infected[name][0]} of scanners as: {self.infected[name][1]}")


    def get_report(self):
        """
        Retrieve file scan reports by scan ID returned by scan endpoint:
        # The resource argument can be also be the MD5, SHA-1 or SHA-256 of a file you want to retrieve
        recent antivirus report.
        """
        url = self.base_url + 'file/report'
        for id in self.scan_id_list:
            counter = 0
            response_code = -2
            inf_scan = []
            while response_code == -2:
                try:
                    time.sleep(20)
                    params = {'apikey': self.apiKey, 'resource': id}  # resource: Resource(s) to be retrieved
                    response = requests.get(url, params=params)
                    output = response.json()
                    # If the requested item is still queued for analysis it will be -2
                    response_code = output['response_code']
                    print(output['verbose_msg'])
                # in case of connection error, will print a message and try again
                except requests.exceptions.ConnectionError:
                    counter += 1
                    print(f"Connection Error. trying again #{counter}")

            if output['positives'] > 0:
                # positives meaning Virus Total reported the file as malware by at least one antivirus
                for scan in output['scans']:
                    if output['scans'][scan]['detected'] is True:
                        # fetching information on malware files from all antivirus reported it as malware
                        inf_scan.append(output['scans'][scan]['result'])

            self.result[output['scan_id']] = \
                {'total': output['total'], 'positives': output['positives'], 'scanners':inf_scan}


    def scan(self,file_l):
        """
        Send a file for scanning with VirusTotal
        file_l is a list of file names
        """
        url = self.base_url + 'file/scan'
        params = {'apikey': self.apiKey}

        first = True
        for f in file_l:
            counter = 0
            Flag = True
            if not first:
                time.sleep(20)
            while Flag:  # handling ConnectionError
                try:
                    files = {'file': (f, open(f, 'rb'))}
                    response = requests.post(url, files=files, params=params)
                    first = False
                    Flag = False
                except requests.exceptions.ConnectionError:
                    print(f"Connection Error. trying again #{counter}")
                    Flag = True
                    counter += 1
                    if counter > 6:
                        Flag = False
                        break
                except:
                    print(f"an error has occurred with file {f}")
                    Flag = False

            try:
                reply = response.json()
                print(reply['verbose_msg'])
                scan_id = reply["scan_id"]
                self.scan_id_list.append(scan_id)
                self.files_id_dic[scan_id] = f
            except json.decoder.JSONDecodeError:
                print(response.text)




