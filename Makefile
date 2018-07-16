DIST_DIR := dist

default: clean test agent sdist

clean:
	$(RM) $(DIST_DIR)/*

agent:
	cd objection/agent && npm run build

sdist:
	python setup.py sdist

testupload:
	twine upload dist/* -r testpypi

upload:
	twine upload dist/*

test:
	python -m unittest
