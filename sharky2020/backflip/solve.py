import base64
import binascii
from Crypto.Cipher import AES
import requests

orig = "3SBqciftaGS8gV24fu0%2B28%2FwaKbZ%2FlxO%2F2nh65Qmhf8bTifD%2Bp24hqgTHaALDahreH%2B5EO%2BoYiVuqea4owrDZsfOvlOcPzDqB5CxGx3b1UQ%3D"
pt = "{\"id\":652,\"is_admin\":0,\"username\":\"kumasankumasan\"}"

def penc(t):
    return base64.b64encode(t).replace('+','%2B').replace('/', '%2F').replace('=', '%3D')

def pdec(t):
    return base64.b64decode(t.replace('%2B', '+').replace('%2F', '/').replace('%3D', '='))

# flip admin -> 1
trunc = pdec(orig)[0x10:]
print len(trunc), binascii.hexlify(trunc), ord(trunc[5])
trunc = trunc[:5]+chr(ord(trunc[5])^1)+trunc[6:]
print len(trunc), binascii.hexlify(trunc)

# forge stream
# ans = chr(125)+chr(174)+chr(32)+chr(6)+chr(205)+chr(140)+chr(239) + chr(132)
ans = chr(13)+chr(49)+chr(33)+chr(21)+chr(216)+chr(37)+chr(209)+chr(40)+chr(125)+chr(174)+chr(32)+chr(6)+chr(205)+chr(140)+chr(239) + chr(132)
while(len(ans) < 0x10):
    for i in range(0x100):
        print i
        tmp = chr(i)
        token = penc(chr(0x1)*(0x10-len(ans)-1)+tmp+ans+trunc) 
        print "token:", token
        cookie = {
            "__cfduid": "df5bf7c793d124429a3fcdc86071c8f101588979592",
            "debug": "true",
            "authentication_token": token 
        }
        r = requests.get('http://backflip_in_the_kitchen.sharkyctf.xyz/profile.php', cookies=cookie)
        if pt[0x10-len(ans)-1:0x10] in r.text:
            print r.text
            ans = tmp + ans 
            break

print "USE THIS:", penc(ans+trunc)
