import monkey
import os

if monkey.init(None, 0, 0, None) == False:
    os._exit(1)
if monkey.start() == False:
    os._exit(1)
if monkey.stop() == False:
    os._exit(1)
