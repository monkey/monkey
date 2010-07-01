import re

test = "127.0.0.1 - [2009-10-02 12:34:44 -400] HEAD /linux.jpg 200 29292\r\n"

c = re.compile("^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})( - )(\[.*\])(\W.*)(\/.* )(\d.* )(.*)(\r\n)$")
print c.split(test)
