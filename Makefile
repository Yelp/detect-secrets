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
