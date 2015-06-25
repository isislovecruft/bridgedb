
.PHONY: install test
.DEFAULT: install test

TRIAL:=$(shell which trial)
VERSION:=$(shell git describe)

all: uninstall clean install coverage-test

test:
	python setup.py test

pep8:
	find bridgedb/*.py | xargs pep8

pylint:
	pylint --rcfile=./.pylintrc ./bridgedb/

pyflakes:
	pyflakes ./bridgedb/

install:
	-python setup.py compile_catalog
	BRIDGEDB_INSTALL_DEPENDENCIES=0	python setup.py install --record installed-files.txt

force-install:
	-python setup.py compile_catalog
	BRIDGEDB_INSTALL_DEPENDENCIES=0	python setup.py install --force --record installed-files.txt

uninstall:
	touch installed-files.txt
	cat installed-files.txt | xargs rm -rf
	rm installed-files.txt

reinstall: uninstall force-install

translations:
	./maint/get-completed-translations

translations-template:
	python setup.py extract_messages

docs:
	python setup.py build_sphinx --version "$(VERSION)"
	cd build/sphinx/html && \
		zip -r ../"$(VERSION)"-docs.zip ./ && \
		echo "Your package documents are in build/sphinx/$(VERSION)-docs.zip"

clean-docs:
	-rm -rf build/sphinx

clean-coverage-html:
	-rm -rf doc/coverage-html

clean: clean-docs clean-coverage-html
	-rm -rf build
	-rm -rf dist
	-rm -rf bridgedb.egg-info
	-rm -rf _trial_temp

coverage-test:
	coverage run --rcfile=".coveragerc" $(TRIAL) ./test/test_*.py
	coverage report --rcfile=".coveragerc"

coverage-html:
	coverage html --rcfile=".coveragerc"

coverage: coverage-test coverage-html
