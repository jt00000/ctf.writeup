from pwn import *
TARGET = './baby_bear'
HOST = '138.68.67.161'
PORT = 20005

elf = ELF(TARGET)
def start():
    if not args.R:
        # print "local"
        # return process(TARGET)
        # return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
        return process(TARGET, stdout=process.PTY, stdin=process.PTY)
    else:
        print "remote"
        return remote(HOST, PORT)

r = start()
r.recvuntil('says: ')
text = r.recvuntil('\n')[:-1]
# text = "0000000000000000000000000010101010101010101010"
pointer = 0
ans = ""

if text[pointer] == "0":
    ans += "0"
    cur = "3cd"
else:
    ans += "1"
    cur = "346"

pointer += 1
while(pointer < len(text)):
    if cur == "346":
        if text[pointer] == "0":
        # 346 -> 457 -> 41d -> 3a3
            ans += "11"
            cur = "3a3"
        else:
        # 346 -> 3f3
            ans += "0"
            cur = "3f3"
        pointer += 1

    elif cur == "3a3":
        if text[pointer] == "0":
        # 3a3 -> 3b3
            ans += "1"
            cur = "3b3"

        else:
        # 3a3 -> 35c -> 346
            ans += "01"
            cur = "346"
        pointer += 1

    elif cur == "3b3":
        if text[pointer] == "0":
        # 3b3 -> 35c -> 3cd
            ans += "00"
            cur = "3cd"

        else:
        # 3b3 -> 35c -> 346
            ans += "01"
            cur = "346"
        pointer += 1

    elif cur == "3f3":
        if text[pointer] == "0":
        # 3f3 -> 41d -> 3a3
            ans += "1"
            cur = "3a3"

        else:
        # 3f3 -> 41d -> 3ed -> 37e -> 478
            ans += "00"
            cur = "478"
        pointer += 1

    elif cur == "3cd":
        if text[pointer] == "0":
        # 3cd -> 37e -> 394 -> 3a3
            ans += "0111"
            cur = "3a3"

        else:
        # 3cd -> 37e -> 394 -> 478
            ans += "0110"
            cur = "478"
        pointer += 1

    elif cur == "478":
        if text[pointer] == "0":
        # 478 -> 3b3
            ans += "1"
            cur = "3b3"

        else:
        # 478 -> 442 -> 3c7 -> 104 -> 35c
            ans += "001"
            cur = "35c"
        pointer += 1
    elif cur == "35c":
        if text[pointer] == "0":
        # 35c -> 3cd
            ans += "0"
            cur = "3cd"

        else:
        # 35c -> 346
            ans += "1"
            cur = "346"
        pointer += 1
    else:
        "error: unknown state"
        exit()

print ans, len(ans)
ans += '0'*(8 - (len(ans) % 8))

output = ""
for i in range(0, len(ans), 8):
    temp = int(ans[i:i+8][::-1], 2)
    # output += hex(temp)[2:].zfill(2) + ' '
    output += chr(temp)

log.info(text)
# log.info(output)
r.sendlineafter('say? ', output)
r.interactive()
