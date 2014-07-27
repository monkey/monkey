import monkey
import os

monkey.init(None, 0, 0, None)
monkey.start()

n1 = len(monkey.mimetype_list())

monkey.mimetype_add('name1', '1')
monkey.mimetype_add('name2', '2')

n2 = len(monkey.mimetype_list())

if n2 - n1 != 2:
    os._exit(1)

monkey.stop()
