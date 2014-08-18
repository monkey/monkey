import monkey
import os
import subprocess

content = '\0' * 50000

def datacb(vhost, url, get, get_len, post, post_len, header):
    ret = {}
    ret['return'] = 1
    ret['content'] = content
    ret['clen'] = len(ret['content'])
    return ret

monkey.init(None, 0, 0, None)
monkey.set_callback('data', datacb)
monkey.start()
subprocess.call('curl localhost:2001 >/tmp/tmpfile 2>/dev/null', shell=True)
if 'a68b2482a6c645a9738329909861afb3' not in subprocess.check_output('md5sum /tmp/tmpfile', shell=True):
    os._exit(1)
monkey.stop()
