import monkey
import threading
import subprocess

content = 'data'
NUM_THREADS = 10
REQ_PER_THREAD = 10

def datacb(vhost, url, get, get_len, post, post_len, header):
    ret = {}
    ret['return'] = 1
    ret['content'] = content
    ret['content_len'] = len(content)
    return ret

class WorkerThread(threading.Thread):
    def __init__(self, num_requests):
        super(WorkerThread, self).__init__()
        self.num_requests = num_requests
    def run(self):
        for r in range(self.num_requests):
            subprocess.call('curl localhost:2001 1> /dev/null 2> /dev/null', shell=True)

if __name__ == '__main__':
    monkey.init(None, 0, 0, None)
    monkey.set_callback('data', datacb)
    monkey.start()

    threads = []
    for t in range(NUM_THREADS):
        t = WorkerThread(REQ_PER_THREAD)
        threads.append(t)

    [t.start() for t in threads]
    [t.join() for t in threads]

    workers = monkey.scheduler_workers_info()
    for w in workers:
        w.print_info()

    monkey.stop()
