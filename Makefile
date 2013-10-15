
.PHONY: install test
.DEFAULT: install test

all:
	python setup.py build

test:
	python setup.py test

install:
	-python setup.py compile_catalog
	python setup.py install --record installed-files.txt

force-install:
	-python setup.py compile_catalog
	python setup.py install --force --record installed-files.txt

uninstall:
	touch installed-files.txt
	cat installed-files.txt | xargs rm -rf

reinstall: uninstall force-install

translations:
	./maint/get-completed-translations
