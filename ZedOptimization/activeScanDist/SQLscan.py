#!/usr/bin/env python

import json
import os

import tldextract
from dotenv import load_dotenv
from zapv2 import ZAPv2

load_dotenv()

APIKEY = os.getenv('ZAP_APIKEY')
PROXIES = {'http': os.getenv('ZAP_PROXIES_HTTP'),
           'https': os.getenv('ZAP_PROXIES_HTTPS')}
FILEPATH = os.getenv("FILEPATH")
TIMEOUT = os.getenv("TIME_OUT")
PROXIES2 = {'http': 'http://127.0.0.1:1234',
           'https': 'http://127.0.0.1:1234'}


def spider_scan(target):
    zap = ZAPv2(apikey='123',
                proxies=PROXIES)

    sessionName = 'SQLScan'

    zap.core.new_session(name=sessionName, overwrite=True)
    print("spider scan")
    scanID = zap.spider.scan(target)

    while int(zap.spider.status(scanID)) < 100:
        # print('Spider progress %: {}'.format(zap.spider.status(scanID)))

        pass

    # References used
    
    # print(help(zap))
    # print(help(zap.core))
    # print(help(zap.spider))
    # print(help(zap.ascan))


    print(zap.core.sites)
    sites = zap.core.sites

    print(len(sites))
    print(sites)

    print("spider done")
    print ('Hosts: {}'.format(', '.join(zap.core.hosts)))
    return list((map(str, zap.spider.results(scanID))))



def active_scan(target):
    zap = ZAPv2(apikey='234',
                proxies=PROXIES2)
    # print(help(zap.core))
    sessionName = 'SpiderScan'

    zap.core.load_session(name=sessionName)

    # Default zap sessions have timestamps
    # zap.core.load_session('20230622-143019.session')
    print("active scan")


    # Specific scan policy
    scanPolicyName = 'SQL Injection'    

 
    # Scan ids for sql injection 
    # Mapping for all such policies : https://www.zaproxy.org/docs/alerts/
    ascanIds = [40018, 40019, 40020, 40021, 40022, 40024, 90018]
    #  40012, 40014, 40016, 40017]

    # print(help(zap.ascan.scanners))
    zap.ascan.add_scan_policy(scanpolicyname=scanPolicyName)


    ascanIds = ",".join(str(id) for id in ascanIds)
    
    # Disable all active scanners in order to enable only what you need
    zap.ascan.disable_all_scanners(scanpolicyname=scanPolicyName)

    # Enable some active scanners
    zap.ascan.enable_scanners(ids=ascanIds,scanpolicyname=scanPolicyName)

    scanID = zap.ascan.scan(url=target, recurse=True, inscopeonly=None, scanpolicyname=scanPolicyName, method=None, postdata=True)


    # print(scanID)
    zap.core.set_option_timeout_in_secs(int(TIMEOUT))

    while int(zap.ascan.status(scanID)) < 100:
        pass

    print("active scan done")

    return {
        'Hosts': zap.core.hosts,
        'Active Scan Alerts': zap.core.alerts(baseurl=target)
    }


def scan():
    print('start')
    target='https://niweera.gq/'
    try:
        host_list = spider_scan(target)
        alerts = active_scan(target)
        json.dump({
            'target': target,
            'paths': host_list,
            'scan': alerts,
        }, open('{}/{}SQL.json'.format('/home/kushal/Desktop/ray/DistriAttack', tldextract.extract(target).fqdn), "w"))
        print('Completed')
        return 0
    except Exception as e:
        return e


if __name__ =='__main__':
    scan()