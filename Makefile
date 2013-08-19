
.PHONY: install test

all:
	python setup.py build

test:
	python setup.py test

install:
	python setup.py install
