
SHELL=/bin/bash

ifneq		(,$(findstring $(SHELLOPTS),extglob))
SHELLOPTS+=:extglob
endif

.PHONY: install test
.DEFAULT: install test

TRIAL:=$(shell which trial)
VERSION:=$(shell git describe)

BUILD_DIR:=build
DIST_DIR:=dist
DOC_BUILD_DIR:=$(BUILD_DIR)/sphinx
COVERAGE_HTML_DIR:=doc/coverage-html
SOURCE_DIR:=lib/bridgedb
PYC_FILES:=$(shell find "$(strip $(SOURCE_DIR))" -name "*.pyc")
TEST_FILES:=_trial_temp
DESCRIPTOR_FILES:=bridge-descriptors cached-extrainfo cached-extrainfo.new networkstatus-bridges
VIRTUALENV:=$$VIRTUAL_ENV
INSTALL_BASE=/usr/local
ifneq		($(strip $(VIRTUAL_ENV)),)
INSTALL_BASE=$(strip $(VIRTUAL_ENV))
endif
INSTALL_DIR=$(INSTALL_BASE)/lib/python2.7/site-packages
INSTALL_FILES:=$(shell find "$(strip $(INSTALL_DIR))" -name "bridgedb-*")
INSTALL_LOG:=installed-files.txt

all: uninstall clean install coverage-test

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
	BRIDGEDB_INSTALL_DEPENDENCIES=0	python setup.py install --record installed-files.txt

force-install:
	-python setup.py compile_catalog
	BRIDGEDB_INSTALL_DEPENDENCIES=0	python setup.py install --force --record installed-files.txt

ifneq		($(shell find "$$PWD" -name "$(strip $(INSTALL_LOG))"),)
uninstall:
	@if test -f "installed-files.txt" ; then \
		printf "Uninstalling bridgedb-%s...\n" $(VERSION) ; \
		cat installed-files.txt | xargs rm -rf ; \
		rm installed-files.txt ; \
		if test -d "$$VIRTUAL_ENV" ; then \
			echo "Detected that we're inside a virtualenv..." ; \
		fi ; \
		if test -n "$(INSTALL_FILES)" ; then \
			echo "Removing $(INSTALL_FILES)..." ; \
			rm -r $(INSTALL_FILES) ; \
		fi ; \
	fi
else
uninstall:
endif

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

clean-build:
	-rm -rf $(BUILD_DIR)
	-rm -rf lib/bridgedb.egg-info
clean-coverage-html:
	-rm -rf $(COVERAGE_HTML_DIR)
clean-dist:
	-rm -rf $(DIST_DIR)
clean-docs:
	-rm -rf $(DOC_BUILD_DIR)
clean-pyc:
	-rm -rf $(PYC_FILES)
clean-test:
	-rm -rf $(TEST_FILES) $(DESCRIPTOR_FILES)
clean: clean-build clean-coverage-html clean-dist clean-docs clean-pyc clean-test

coverage-test:
	coverage run --rcfile=".coveragerc" $(TRIAL) ./lib/bridgedb/test/test_*.py
	coverage report --rcfile=".coveragerc"

coverage-html:
	coverage html --rcfile=".coveragerc"

coverage: coverage-test coverage-html
