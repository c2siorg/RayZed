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

    sessionName = 'SpiderScan'

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



def scan():
    print('start')
    target='https://niweera.gq/'
    try:
        host_list = spider_scan(target)
        json.dump({
            'target': target,
            'paths': host_list,
        }, open('{}/{}SQL.json'.format('/home/kushal/Desktop/ray/DistriAttack/spider', tldextract.extract(target).fqdn), "w"))
        print('Completed')
        return 0
    except Exception as e:
        return e


if __name__ =='__main__':
    scan()