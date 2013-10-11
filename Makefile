
.PHONY: install test
.DEFAULT: install test

all:
	python setup.py build

test:
	python setup.py test

install:
	python setup.py install --record installed-files.txt

force-install:
	python setup.py install --force --record installed-files.txt 2>&1 >/dev/null

uninstall:
	touch installed-files.txt
	cat installed-files.txt | xargs rm -rf

reinstall: uninstall force-install
