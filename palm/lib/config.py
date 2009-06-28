import ConfigParser

class PalmConfig(ConfigParser.ConfigParser):
    def __init__(self):
        ConfigParser.ConfigParser.__init__(self)

    def readconf(self, path):
        self.read(path)

    def get_handlers(self):
        return self.sections()

