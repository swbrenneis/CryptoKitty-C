.PHONY: clean bigint

all: bigint

bigint:
	$(MAKE) -C bigint

clean:
	cd bigint && $(MAKE) clean

