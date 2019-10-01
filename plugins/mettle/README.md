# objection Mettle plugin

This plugin should sideload [Mettle](https://github.com/rapid7/mettle), loaded as a plugin in objection.
Mettle itself should be a shared library available in this directory.

## installation

Getting Mettle is super simple.

1. Clone the respistory with `git clone https://github.com/rapid7/mettle.git`.
2. Build Mettle for your target architecture. Eg: `make TARGET=aarch64-iphone-darwin`.
3. Codesign the new dylib in the build directory with `codesign -f -s <hash> mettle.dylib`
4. Copy the codesigned dylib into this plugin folder.

Running `plugin mettle load` will grab the new dylib and upload it to the device.
