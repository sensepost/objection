# objection

Installation for now is simply a matter of cloning the repo and doing `pip install --editable .`. This will give you the `objection` command.  
Updating then can be done with just a `git pull`.

## todo:
- unarchive keychain items that are bplist00ԁX$versionX$objectsY$archiverT$top
- detect more argument types in ios arg dumper
- touchid `kSecAccessControlTouchIDAny` keychain item experiment
- generic method return value changes (ie: true -> false)
- script loads on start
- implement `rpc.exports` for the filemanager to help with performance and timeouts
- fix frida exception handling when a Gadget can not be found to connect to via any transport
- add a simulated jailbreak environment, returning true to common calls for jailbreak checks