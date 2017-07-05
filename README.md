![objection](images/objection.png)

Runtime Mobile Exploration

## introduction
`objection` is a runtime mobile exploration toolkit, powered by [frida](https://www.frida.re/), built with the aim of helping security analysts assess mobile applications and their security posture, albeit without the need for a Jailbroken or Rooted device mobile device.

The projects name quite literally explains the approach, whereby platform specific code (and thereby objects) is injected into a running process an executed.

*Note* This is not some form a jailbreak / root bypass. By using `objection`, you are still limited by all of the restrictions imposed by the applicable sandbox you are facing, however, you now have a familiar interface to explore the filesystem and inner workings of the application in question.

## installation
Installation for now is simply a matter of cloning this repistory and doing `pip install --editable .`. This will give you the `objection` command.  

## updating
Updating can be done with just a `git pull` in the clonsed respositories path.

## todo:
There is still a ton of work left to do.

- Android support! Soon™
- unarchive keychain items that are bplist00ԁX$versionX$objectsY$archiverT$top
- detect more argument types in ios arg dumper
- touchid `kSecAccessControlTouchIDAny` keychain item experiment
- generic method return value changes (ie: true -> false)
- script loads on start
- implement `rpc.exports` for the filemanager to help with performance and timeouts
- fix frida exception handling when a Gadget can not be found to connect to via any transport
- add a simulated jailbreak environment, returning true to common calls for jailbreak checks
