
DST=compiled.gen

all: compile

verify:
	gene -r ./rules -verify

compile: verify
	gene -r ./rules -dump '.*' > $(DST)
	shasum -a 256 $(DST) > $(DST).sha256
