#!/usr/bin/env python3
import os
import requests
import argparse
import json
import time

def send_req(ip, format, key, api):
    querystring = {
        'ipAddress': ip
    }
    headers = {
        'Accept': 'application/json',
        'Key': key
    }
    response = requests.request(method='GET', url=api, headers=headers, params=querystring)
    time.sleep(5)
    if(response.headers['X-RateLimit-Remaining'] == 0 or response.status_code == 429):
        print("Rate Limiting reached. Got 429 error!")
        exit()
    response = json.loads(response.text)
    try:
        if(response['errors'] is not None):
            return "AbuseIPDB returned an error for " + ip + " " + response['errors'][0]['detail']
    except:        
        if(format == "csv"):
            return "" + ip +"," + str(response['data']['totalReports']) + "," + str(response['data']['domain']) + "," + str(response['data']['usageType']) + "," + str(response['data']['isp']) + "," + str(response['data']['abuseConfidenceScore']) + "," + str(response['data']['isWhitelisted']) + "," + str(response['data']['lastReportedAt'])

def main():
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('--format')
        parser.add_argument('--file')
        parser.add_argument('--ip')
        parser.add_argument('--key')
        parser.add_argument('--api')
        args = parser.parse_args()

        if(args.file is not None):
            ips = (open(args.file).read()).split("\n")
            if args.format == "csv":
                print("Generating a report .....!")            
                f = open("report.csv", "a")
                f.write('IP Address,Total Reports,Domain,Usage Type,ISP,Abuse Confidence Score,Is Whitelisted,Last Reported At' + "\n")
            
                for i in ips:
                    resp = send_req(i, args.format, args.key, args.api)
                    if "error" not in resp:                
                        f = open("report.csv", "a")
                        f.write(str(resp) + "\n")
                
                    elif(args.ip is not None):
                        if args.format == "csv":
                            print("Generating a report .....!")            
                            f = open("report.csv", "a")
                            f.write('IP Address,Total Reports,Domain,Usage Type,ISP,Abuse Confidence Score,Is Whitelisted,Last Reported At' + "\n")
            
                            resp = send_req(args.ip, args.format, args.key, args.api)
                            if "error" not in resp:            
                                f = open("report.csv", "a")
                                f.write(str(resp) + "\n") 
          
    except Exception as e:
        print(e)        

if __name__ == "__main__":
    main()
