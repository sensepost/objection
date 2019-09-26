# objection Flex plugin

This plugin should sideload Flex[1], loaded as a plugin in objection.
Flex itself should be a shared library (with your target's architecture as either a thin/fat Mach-o).

The source code for a shared library called libFlex is included in this gist as .h and .m files. You need to copy the `Classes/` directory from the official Flex project[1] into your project and compile that as a shared library.

[1] [https://github.com/Flipboard/FLEX](https://github.com/Flipboard/FLEX)  
