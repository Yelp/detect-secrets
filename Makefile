PROJECT_DIR := $(shell pwd)

.PHONY: minimal
minimal: setup

.PHONY: setup
setup:
	tox -e venv

.PHONY: install-hooks
install-hooks:
	tox -e pre-commit -- install -f --install-hooks

.PHONY: test
test:
	tox

.PHONY: clean
clean:
	find -name '*.pyc' -delete
	find -name '__pycache__' -delete

.PHONY: super-clean
super-clean: clean
	rm -rf .tox
	rm -rf venv

.PHONY: fix-db2-mac
fix-db2-mac:
	# comment out lines for any interpreters that aren't installed on your machine
	install_name_tool -change libdb2.dylib $(PROJECT_DIR)/.tox/py27/lib/python2.7/site-packages/clidriver/lib/libdb2.dylib $(PROJECT_DIR)/.tox/py27/lib/python2.7/site-packages/ibm_db.so
	install_name_tool -change libbd2.dylib $(PROJECT_DIR)/.tox/py35/lib/python3.5/site-packages/clidriver/lib/libdb2.dylib $(PROJECT_DIR)/.tox/py35/lib/python3.5/site-packages/ibm_db.cpython-35m-darwin.so
	install_name_tool -change libbd2.dylib $(PROJECT_DIR)/.tox/py36/lib/python3.6/site-packages/clidriver/lib/libdb2.dylib $(PROJECT_DIR)/.tox/py36/lib/python3.6/site-packages/ibm_db.cpython-36m-darwin.so
	install_name_tool -change libdb2.dylib $(PROJECT_DIR)/.tox/py37/lib/python3.7/site-packages/clidriver/lib/libdb2.dylib $(PROJECT_DIR)/.tox/py37/lib/python3.7/site-packages/ibm_db.cpython-37m-darwin.so
	install_name_tool -change libdb2.dylib $(PROJECT_DIR)/.tox/pypy/site-packages/clidriver/lib/libdb2.dylib $(PROJECT_DIR)/.tox/pypy/site-packages/ibm_db.pypy-41.so
	install_name_tool -change libdb2.dylib $(PROJECT_DIR)/.tox/pypy3/site-packages/clidriver/lib/libdb2.dylib $(PROJECT_DIR)/.tox/pypy3/site-packages/ibm_db.pypy3-71-darwin.so
