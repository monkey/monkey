import monkey
import os

if not monkey.init(None, 0, 0, None):
    os._exit(1)
if not monkey.stop():
    os._exit(1)
