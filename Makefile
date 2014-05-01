
.PHONY: install test
.DEFAULT: install test

TRIAL:=$(shell which trial)

all:
	python setup.py build

test:
	python setup.py test

pep8:
	find lib/bridgedb/*.py | xargs pep8

pylint:
	pylint --rcfile=./.pylintrc ./lib/bridgedb/

pyflakes:
	pyflakes lib/bridgedb/

install:
	-python setup.py compile_catalog
	python setup.py install --record installed-files.txt

force-install:
	-python setup.py compile_catalog
	python setup.py install --force --record installed-files.txt

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
	python setup.py build_sphinx

clean-docs:
	-rm -rf build/sphinx

clean:
	-rm -rf build
	-rm -rf dist
	-rm -rf lib/bridgedb.egg-info
	-rm -rf _trial_temp

coverage-test:
	-coverage run --rcfile=".coveragerc" $(TRIAL) ./lib/bridgedb/test/test_*.py
	-coverage report --rcfile=".coveragerc"

coverage-html:
	-coverage html --rcfile=".coveragerc"

coverage: coverage-test coverage-html
