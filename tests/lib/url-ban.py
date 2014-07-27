import monkey
import os

def datacb(vhost, url, get, get_len, post, post_len, header):
    os._exit(1)

def urlch(string):
    return 0

monkey.init(None, 0, 0, None)
monkey.set_callback('data', datacb)
monkey.set_callback('url', urlch)
monkey.start()
os.system('wget -q -t2 -O /dev/null localhost:2001')
monkey.stop()
