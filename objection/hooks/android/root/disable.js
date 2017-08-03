// Attempts to disable root detection.
// Again, a weird thing considering what objection tries to do,
// but there may be cases where this makes sense.

var String = Java.use('java.lang.String');
var Runtime = Java.use('java.lang.Runtime');
var IOException = Java.use('java.io.IOException');
var File = Java.use('java.io.File');

var common_paths = [
    '/data/local/bin/su',
    '/data/local/su',
    '/data/local/xbin/su',
    '/dev/com.koushikdutta.superuser.daemon/',
    '/sbin/su',
    '/system/app/Superuser.apk',
    '/system/bin/failsafe/su',
    '/system/bin/su',
    '/system/etc/init.d/99SuperSUDaemon',
    '/system/sd/xbin/su',
    '/system/xbin/busybox',
    '/system/xbin/daemonsu',
    '/system/xbin/su',
];

// 'test-keys' check.
String.contains.implementation = function (check) {

    if (check == 'test-keys') {

        send(JSON.stringify({
            status: 'success',
            error_reason: NaN,
            type: 'root-bypass',
            data: 'Check for test-keys was detected. Marking it as failed.'
        }));

        return false;
    }

    // call the original method
    this.contains.apply(this, arguments);
}

// exec check for su command.
Runtime.exec.overload('java.lang.String').implementation = function (command) {

    if (command.endsWith('su')) {

        send(JSON.stringify({
            status: 'success',
            error_reason: NaN,
            type: 'root-bypass',
            data: 'Check for su detected with command \'' + command + '\'. Throwing an IOExeption.'
        }));

        throw IOException.$new('anti-root');
    }

    // call the original method
    this.contains.apply(this, arguments);
}

// file existance checks.
File.exists.implementation = function () {

    // grab the filename we are working with
    var filename = this.getAbsolutePath();

    // check if the looked up path is in the list of common_paths
    if (common_paths.indexOf(filename) >= 0) {

        send(JSON.stringify({
            status: 'success',
            error_reason: NaN,
            type: 'root-bypass',
            data: 'Check for \'' + filename + '\' was detected. Returning false.'
        }));

        return false
    }

    // call the original method
    this.contains.apply(this, arguments);
}
