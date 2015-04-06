all:
	@$(MAKE) -C build/

install:
	@$(MAKE) -C build/ install
clean:
	@$(MAKE) -C build/ clean
