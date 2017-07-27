// Attempts to simulate a Jailbroken device by responding to
// common types of checks positively.

var common_paths = [
    '/bin/sh',
    '/etc/apt',
    '/bin/bash',
    '/usr/bin/ssh',
    '/usr/bin/sshd',
    '/var/cache/apt',
    '/usr/sbin/sshd',
    '/var/lib/cydia',
    '/var/log/syslog',
    '/usr/bin/cycript',
    '/var/tmp/cydia.log',
    '/private/var/stash',
    '/etc/ssh/sshd_config',
    '/Applications/Icy.app',
    '/Applications/Cydia.app',
    '/usr/libexec/ssh-keysign',
    '/usr/libexec/sftp-server',
    '/Applications/MxTube.app',
    '/usr/libexec/sftp-server',
    '/Applications/RockApp.app',
    '/private/var/tmp/cydia.log',
    '/Applications/blackra1n.app',
    '/Applications/FakeCarrier.app',
    '/Applications/SBSetttings.app',
    '/Applications/WinterBoard.app',
    '/Applications/IntelliScreen.app',
    '/Library/MobileSubstrate/MobileSubstrate.dylib',
    '/System/Library/LaunchDaemons/com.ikey.bbot.plist',
    '/Library/MobileSubstrate/DynamicLibraries/Veency.plist',
    '/System/Library/LaunchDaemons/com.saurik.Cy@dia.Startup.plist',
];

// Hook NSFileManager calls and check if it is to a common path.
// TODO: Hook fopen too.
Interceptor.attach(ObjC.classes.NSFileManager['- fileExistsAtPath:'].implementation, {
    onEnter: function (args) {

        // Use a marker to check onExit if we need to manipulate
        // the response.
        this.is_common_path = false;

        // Extract the path
        this.path = ObjC.Object(args[2]).toString();

        // check if the looked up path is in the list of common_paths
        if (common_paths.indexOf(this.path) >= 0) {

            // Mark this path as one that should have its response
            // modified if needed.
            this.is_common_path = true;
        }
    },
    onLeave: function (retval) {

        // check if the method call matched a common_path.
        // if thats the case, respond with success instead if needed.
        if (this.is_common_path) {

            if (retval == 0x0) {

                send(JSON.stringify({
                    status: 'success',
                    error_reason: NaN,
                    type: 'jailbreak-simulate',
                    data: 'A failed lookup for ' + this.path + ' occurred. Marking it as successful.'
                }));

                retval.replace(0x1);
            }
        }
    }
});

// Hook fork() in libSystem.B.dylib and return 0
// TODO: Hook vfork
var libSystem_B_dylib_fork = Module.findExportByName('libSystem.B.dylib', 'fork');
Interceptor.attach(libSystem_B_dylib_fork, {
    onLeave: function (retval) {

        send(JSON.stringify({
            status: 'success',
            error_reason: NaN,
            type: 'jailbreak-simulate',
            data: 'Making call to libSystem.B.dylib::fork() return 0x1'
        }));

        retval.replace(0x1);
    }
});
