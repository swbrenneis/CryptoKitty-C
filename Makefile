.PHONY: clean bigint

all: data random

data:
	$(MAKE) -C data

random:
	$(MAKE) -C random

clean:
	cd data && $(MAKE) clean
	cd random && $(MAKE) clean

