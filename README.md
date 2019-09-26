# 📱objection - Runtime Mobile Exploration

`objection` is a runtime mobile exploration toolkit, powered by [Frida](https://www.frida.re/), built to help you assess the security posture of your mobile applications, without needing a jailbreak.

<img align="right" src="./images/objection.png" height="220" alt="objection">

## key features

- Supports both iOS and Android.
- Inspect and interact with container file systems.
- Bypass SSL pinning.
- Dump keychains.
- Perform memory related tasks, such as dumping & patching.
- Explore and manipulate objects on the heap.
- And much, much [more](https://github.com/sensepost/objection/wiki/Features)...

Screenshots are available in the [wiki](https://github.com/sensepost/objection/wiki/Screenshots).

[![Twitter](https://img.shields.io/badge/Twitter-%40leonjza-blue.svg)](https://twitter.com/leonjza)
[![PyPi](https://badge.fury.io/py/objection.svg)](https://pypi.python.org/pypi/objection)
[![Travis](https://travis-ci.org/sensepost/objection.svg?branch=master)](https://travis-ci.org/sensepost/objection)

## installation

Installation is simply a matter of `pip3 install objection`. This will give you the `objection` command.

For more detailed update and installation instructions, please refer to the wiki page [here](https://github.com/sensepost/objection/wiki/Installation).

## sample usage

A sample session, where `objection` version 0.1 is used to explore the applications environment. Newer versions have the REPL prompt set to the current applications name, however usage has remained the same.

[![asciicast](https://asciinema.org/a/8O6fjDHOdVKgPYeqITHXPp6HV.png)](https://asciinema.org/a/8O6fjDHOdVKgPYeqITHXPp6HV)

## license

`objection` is licensed under a [GNU General Public v3 License](https://www.gnu.org/licenses/gpl-3.0.en.html). Permissions beyond the scope of this license may be available at [http://sensepost.com/contact/](http://sensepost.com/contact/).
