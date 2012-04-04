DIRS    = base64 json sha1 sqlite

all:
	@(for d in $(DIRS); do $(MAKE) -C $$d; done)

clean:
	@(for d in $(DIRS); do $(MAKE) -C $$d clean; done)
	rm -rf *.dpkg

