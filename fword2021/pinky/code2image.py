from PIL import Image

w, h = 200, 30 # any (w, h) -> "w * h > 5934"
new_img = Image.new("RGB", (w,h))

with open("./mycode", 'r') as f:
	code = f.read()
code = code.ljust(w*h, '+')

assert(len(code) == w*h)

colors = {
	'>': (255,0,0),
	'.': (0,255,0),
	'<': (0,0,255),
	'+': (255,255,0),
	'-': (0,255,255),
	'[': (255,0,188),
	']': (255, 128,0),
	',': (102,0,204)
	}

i = 0
cnt = 0
for y in range(h):
	for x in range(w):
		pix = colors[code[cnt]]
		cnt += 1
		print(x, y)
		print(code[y*w+x], pix)
		new_img.putpixel((x, y), pix)

new_img.save("./out.png")
