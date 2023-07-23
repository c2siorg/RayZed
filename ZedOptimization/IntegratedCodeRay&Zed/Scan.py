import ray
import hashlib

import json
import os

import tldextract
from zapv2 import ZAPv2

import time

import shutil


ray.init()


@ray.remote
class Scan:
    def __init__(self, target):
        self.target = target
        self.hash = hashlib.md5(target.encode()).hexdigest()
        return self.hash

    def spider_scan(self):

        PROXIES = {'http': 'http://127.0.0.1:1234',
           'https': 'http://127.0.0.1:1234'}

        zap = ZAPv2(apikey='234',
                    proxies=PROXIES)

        sessionName = str(self.hash)

        # Initializing a session
        zap.core.new_session(name=sessionName, overwrite=True)
        print("spider scan")
        scanID = zap.spider.scan(self.target)

        while int(zap.spider.status(scanID)) < 100:

            pass
        
        isExist = os.path.exists(f'/home/kushal/Desktop/ray/temp1/session/{sessionName}.session')

        # print(isExist)

        sites = zap.core.sites
        print(sites)

        print("spider done")
        print ('Hosts: {}'.format(', '.join(zap.core.hosts)))

        json.dump({
            'target': self.target,
            'path': list((map(str, zap.spider.results(scanID)))),
        }, open('{}/{}SpiderScan.json'.format('/home/kushal/Desktop/ray/distributed/results', tldextract.extract(self.target).fqdn), "w"))

        return list((map(str, zap.spider.results(scanID))))

    # First active scan chunk
    def active_scan_1(self):

        
        PROXIES2 = {'http': 'http://127.0.0.1:2345',
           'https': 'http://127.0.0.1:2345'}

        zap = ZAPv2(apikey='100',
                    proxies=PROXIES2)

        sessionName = str(self.hash)
        
        src = '/home/kushal/Desktop/ray/temp1/session/'
        dst = '/home/kushal/Desktop/ray/temp2/session/'

        isExistsrc = os.path.exists(f'{src}{sessionName}.session.log')

        # print(isExistsrc)

        if(isExistsrc == False):
            time.sleep(30)


        isExist = os.path.exists(f'{dst}{sessionName}.session.log')
        # print(isExist)
        # Copying necessary session files
        if(isExist == False):
           shutil.copy(f'{src}{sessionName}.session.log', dst)
           shutil.copy(f'{src}{sessionName}.session', dst)
           shutil.copy(f'{src}{sessionName}.session.properties', dst)
           shutil.copy(f'{src}{sessionName}.session.data', dst)
           shutil.copy(f'{src}{sessionName}.session.script', dst)

        shutil.copy(f'{src}{sessionName}.session.log', dst)

        # Loading spider scan session
        zap.core.load_session(name=sessionName)

        print("active scan 1")


        # Specific scan policy
        scanPolicyName = f'{sessionName}_SQL_Injection'    

    
        # Scan ids for sql injection 
        # Mapping for all such policies : https://www.zaproxy.org/docs/alerts/
        ascanIds = [40018, 40019, 40020, 40021, 40022, 40024, 90018]

        # print(help(zap.ascan.scanners))
        zap.ascan.add_scan_policy(scanpolicyname=scanPolicyName)


        ascanIds = ",".join(str(id) for id in ascanIds)
        
        # Disable all active scanners in order to enable only what you need
        zap.ascan.disable_all_scanners(scanpolicyname=scanPolicyName)

        # Enable some active scanners
        zap.ascan.enable_scanners(ids=ascanIds,scanpolicyname=scanPolicyName)

        scanID = zap.ascan.scan(url=self.target, recurse=True, inscopeonly=None, scanpolicyname=scanPolicyName, method=None, postdata=True)


        # print(scanID)
        zap.core.set_option_timeout_in_secs(int(60))

        while int(zap.ascan.status(scanID)) < 100:
            pass

        print("active scan 1 done")

        json.dump({
            'target': self.target,
            'scan': zap.core.alerts(baseurl=self.target),
        }, open('{}/{}ActiveScan1.json'.format('/home/kushal/Desktop/ray/distributed/results', tldextract.extract(self.target).fqdn), "w"))

        return {
            'Hosts': zap.core.hosts,
            'Active Scan Alerts': zap.core.alerts(baseurl=self.target)
        }

    # Second active scan chunk
    def active_scan_2(self):
        
        PROXIES3 = {'http': 'http://127.0.0.1:3456',
           'https': 'http://127.0.0.1:3456'}

        zap = ZAPv2(apikey='300',
                    proxies=PROXIES3)

        sessionName = str(self.hash)
        
        src = '/home/kushal/Desktop/ray/temp1/session/'
        dst = '/home/kushal/Desktop/ray/temp3/session/'

        isExistsrc = os.path.exists(f'{src}{sessionName}.session.log')

        # print(isExistsrc)

        if(isExistsrc == False):
            time.sleep(30)


        isExist = os.path.exists(f'{dst}{sessionName}.session.log')
        # print(isExist)
        # Copying necessary session files
        if(isExist == False):
           shutil.copy(f'{src}{sessionName}.session.log', dst)
           shutil.copy(f'{src}{sessionName}.session', dst)
           shutil.copy(f'{src}{sessionName}.session.properties', dst)
           shutil.copy(f'{src}{sessionName}.session.data', dst)
           shutil.copy(f'{src}{sessionName}.session.script', dst)

        shutil.copy(f'{src}{sessionName}.session.log', dst)

        # Loading spider scan session
        zap.core.load_session(name=sessionName)

        print("active scan 2")


        # Specific scan policy
        scanPolicyName = f'{sessionName}_XSS_Scan'    

    
        # Scan ids for sql injection 
        # Mapping for all such policies : https://www.zaproxy.org/docs/alerts/
        ascanIds = [40012, 40014, 40016, 40017]

        # print(help(zap.ascan.scanners))
        zap.ascan.add_scan_policy(scanpolicyname=scanPolicyName)


        ascanIds = ",".join(str(id) for id in ascanIds)
        
        # Disable all active scanners in order to enable only what you need
        zap.ascan.disable_all_scanners(scanpolicyname=scanPolicyName)

        # Enable some active scanners
        zap.ascan.enable_scanners(ids=ascanIds,scanpolicyname=scanPolicyName)

        scanID = zap.ascan.scan(url=self.target, recurse=True, inscopeonly=None, scanpolicyname=scanPolicyName, method=None, postdata=True)


        # print(scanID)
        zap.core.set_option_timeout_in_secs(int(60))

        while int(zap.ascan.status(scanID)) < 100:
            pass

        print("active scan 2 done")

        json.dump({
            'target': self.target,
            'scan': zap.core.alerts(baseurl=self.target),
        }, open('{}/{}ActiveScan2.json'.format('/home/kushal/Desktop/ray/distributed/results', tldextract.extract(self.target).fqdn), "w"))


        return {
            'Hosts': zap.core.hosts,
            'Active Scan Alerts': zap.core.alerts(baseurl=self.target)
        }



if __name__ =='__main__':

    DATA = [
        'https://niweera.gq/'
    ]

    # Instantiating Scan Actor objects
    ids = [Scan.remote(i) for i in DATA]

    # Using spider method for Scan Actor objects
    spider_scan_list = [id.spider_scan.remote() for id in ids]

    id_to_index = {}

    index = 0

    # Mapping spider scan objects to initial total actor object of scan
    for x in spider_scan_list:
        id_to_index[x] = index
        index + 1
    
    # print(id_to_index)

    print(spider_scan_list)

    unfinished = spider_scan_list
    while unfinished:
        finished, unfinished = ray.wait(unfinished, num_returns=1)

        index_done = id_to_index[finished[0]]
        
        print(finished[0])
        spider_result = ray.get(finished)
        # print(spider_result)

        # Using active scan methods only for actors whose spider scan completed
        act_scan_1 = ids[index_done].active_scan_1.remote()
        act_scan_2 = ids[index_done].active_scan_2.remote()

        active_result = ray.get([act_scan_1, act_scan_2])
