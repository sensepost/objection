DIST_DIR := dist

default: clean test frida-agent sdist

clean:
	$(RM) $(DIST_DIR)/*

frida-agent:
	cd agent && yarn install --non-interactive && yarn build

sdist:
	python3 setup.py sdist

testupload:
	twine upload dist/* -r testpypi

upload:
	twine upload dist/*

test:
	python -m unittest

build-docker:
	docker build --platform linux/amd64 --tag objection:latest .
