// Attempts to disable Jailbreak detection.
// This seems like an odd thing to do on a device that is probably not
// jailbroken. However, in the case of a device losing a jailbreak due to
// an OS upgrade, some filesystem artifacts may still exist, causing some
// of the typical checks to incorrectly detect the jailbreak status!

// Get the common_paths for iOS
//jinja: include 'ios/jailbreak/_common_paths.js'

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
        // if that's the case, respond with a failure instead if needed.
        if (this.is_common_path) {

            if (retval != 0x0) {

                send({
                    status: 'success',
                    error_reason: NaN,
                    type: 'jailbreak-bypass',
                    data: 'A successful lookup for ' + this.path + ' occurred. Marking it as failed.'
                });

                retval.replace(0x0);
            }
        }
    }
});

// Hook fork() in libSystem.B.dylib and return 0
// TODO: Hook vfork
var libSystem_B_dylib_fork = Module.findExportByName('libSystem.B.dylib', 'fork');

if (libSystem_B_dylib_fork) {

    Interceptor.attach(libSystem_B_dylib_fork, {
        onLeave: function (retval) {

            send({
                status: 'success',
                error_reason: NaN,
                type: 'jailbreak-bypass',
                data: 'Making call to libSystem.B.dylib::fork() return 0x0'
            });

            retval.replace(0x0);
        }
    });
} else {

    send({
        status: 'error',
        error_reason: 'Unable to find libSystem.B.dylib::fork(). Running on simulator?',
        type: 'jailbreak-bypass',
        data: NaN
    });
}
