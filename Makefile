
.PHONY: install test

all:
	python setup.py build

test:
	python setup.py test

install:
	python setup.py install --record installed-files.txt

uninstall:
	touch installed-files.txt
	cat installed-files.txt | xargs rm -rf
