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


def spider_scan(target):
    zap = ZAPv2(apikey=APIKEY,
                proxies=PROXIES)
    scanID = zap.spider.scan(target)

    while int(zap.spider.status(scanID)) < 100:
        pass

    return list((map(str, zap.spider.results(scanID))))


def passive_scan():
    zap = ZAPv2(apikey=APIKEY,
                proxies=PROXIES)

    while int(zap.pscan.records_to_scan) > 0:
        pass

    return {
        'Hosts': zap.core.hosts,
        'Active Scan Alerts': zap.core.alerts()
    }


def active_scan(target):
    zap = ZAPv2(apikey=APIKEY,
                proxies=PROXIES)
    scanID = zap.ascan.scan(target)
    zap.core.set_option_timeout_in_secs(int(TIMEOUT))
    while int(zap.ascan.status(scanID)) < 100:
        pass

    return {
        'Hosts': zap.core.hosts,
        'Active Scan Alerts': zap.core.alerts(baseurl=target)
    }


def scan(target):
    try:
        host_list = spider_scan(target)
        alerts = active_scan(target)
        json.dump({
            'target': target,
            'paths': host_list,
            'scan': alerts,
        }, open('{}/{}.json'.format(FILEPATH, tldextract.extract(target).fqdn), "w"))
        return 0
    except Exception as e:
        return e
