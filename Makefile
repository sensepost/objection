DIST_DIR := dist

default: clean frida-agent sdist

clean:
	$(RM) $(DIST_DIR)/*

frida-agent:
	cd agent && npm run build

sdist:
	uv build

testupload:
	uv publish --index testpypi

upload:
	uv publish
