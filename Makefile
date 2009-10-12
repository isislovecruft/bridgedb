
all:
	python setup.py build

test:
	python setup.py test

install:
	@echo 'To install, run python setup.py --prefix=$$HOME'
