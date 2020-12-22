from Crypto.Cipher import AES
from binascii import unhexlify, hexlify

'''
nonce = unhexlify("08da1c85456baf1f49ef5537")
assert(len(nonce) == 0xc)
# key =  unhexlify("39db05e472d17e5971a71ace731dd762e52d05e0512d7e04c15c5d8603f38bbc")
key = unhexlify(''.join("38 e1 4c 90 11 00 ea 97 e1 dd c5 e3 34 a3 8b 62 c9 e5 8f d0 69 75 07 ac dc 91 99 5c 11 e0 92 ea".split(' ')))
'''

def gcm_encrypt(nonce, key, note, text):
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    cipher.update(note)
    ct, tag = cipher.encrypt_and_digest(text)
    return ct, tag

def gcm_decrypt(nonce, key, note, ct, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    cipher.update(note)
    pt = cipher.decrypt_and_verify(ct, tag)
    return pt

'''
assert(len(key) == 32)

note = "\x00"*0x8
text = chr(ord('g')|0x80)+'eampara'+'A'*0x78

cipher = AES.new(key, AES.MODE_GCM, nonce)
cipher.update(note)
out, tag = cipher.encrypt_and_digest(text)
print hexlify(out)
print "-----"
print hexlify(tag)
print "-----"

text = chr(ord('g'))+'eampara'+'A'*0x78
cipher = AES.new(key, AES.MODE_GCM, nonce)
cipher.update(note)
out, tag = cipher.encrypt_and_digest(text)
print hexlify(out)
print "-----"
print hexlify(tag)
print "-----"

print hexlify(nonce)
cipher = AES.new(key, AES.MODE_GCM, nonce)
cipher.update(note)
pt = cipher.decrypt_and_verify(out, tag)

print hexlify(pt)
'''



