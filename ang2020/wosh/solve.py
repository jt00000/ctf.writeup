import logging
import requests
import json
from websocket import create_connection

URL = "https://woooosh.2020.chall.actf.co"
# arg = "/socket.io/?EIO=3&transport=polling&t=N3SewkA"
arg = "/socket.io/?EIO=3&transport=polling&t=1000000000000000"

# logging.basicConfig()
# logging.getLogger().setLevel(logging.DEBUG)
# requests_log = logging.getLogger("requests.packages.urllib3")
# requests_log.setLevel(logging.DEBUG)
# requests_log.propagate = True

while(1):
    flag = True
    s = requests.Session()
    ret = s.get(URL+arg)
    print ret.content
    # print len(ret.content)
    sid = ret.content.split('"')[3]
    
    payload = "11:42[\"start\"]"
    ret = s.post(URL+arg+"&sid="+sid, data=payload)
    # print ret.content
    # print len(ret.content)
    
    for i in range(21):
        ret = s.get(URL+arg+"&sid="+sid)
        if "No flag for you!" in ret.content:
            flag = False
            print "too late | score: ", score
            print ret.content
            s.close()
            break
        
        ret = ret.content.split('"')
        x = int(ret[4][1:-1])
        y = int(ret[6][1:].split('}')[0])
        score = int(ret[-1][1:-1])
        print "score = ", score, ", pos = (", x, ", ", y, ")"
    
        payload = ":42[\"click\", "+str(x)+", "+str(y)+"]"
        payload = str(len(payload)-1) + payload
        ret = s.post(URL+arg+"&sid="+sid, data=payload)
        # print ret.content
        # print len(ret.content)
    
    if flag == True:
        break

print "win"
ret = s.get(URL+arg+"&sid="+sid)
print ret.content

