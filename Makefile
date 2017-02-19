build:
	stack build hs-net-icmp

clean:
	stack clean

test:
	stack test

tags:
	hasktags-generate .

sources:
	stack-unpack-dependencies

.PHONY: build clean tags sources test
