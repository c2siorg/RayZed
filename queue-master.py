'''
Next steps
  To connect to this Ray runtime from another node, run
    ray start --address='10.4.8.124:6666' --redis-password='5241590000000000'

  Alternatively, use the following Python code:
    import ray
    ray.init(address='auto', _redis_password='5241590000000000')

  If connection fails, check your firewall settings and network configuration.

  To terminate the Ray runtime, run
    ray stop
'''

import ray

from Scan import scan

ray.init()


@ray.remote
def zap_scan(target):
    return scan(target)


DATA = [
    'https://rdesilva.us/',
    'https://niweera.gq/',
    'https://urlabuse.com/',
    'https://www.zaproxy.org/'
]

refs = [zap_scan.remote(i) for i in DATA]

unfinished = refs
while unfinished:
    finished, unfinished = ray.wait(unfinished, num_returns=1)
    result = ray.get(finished)
    print(result)
