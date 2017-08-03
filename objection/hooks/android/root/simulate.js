// Attempts to simulate a rooted device by responding positively
// to common checks that are performed by applications.

var String = Java.use('java.lang.String');
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
            type: 'root-simulate',
            data: 'Check for test-keys was detected. Marking it as successful.'
        }));

        return true;
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
            type: 'root-simulate',
            data: 'Check for \'' + filename + '\' was detected. Returning true.'
        }));

        return true
    }

    // call the original method
    this.contains.apply(this, arguments);
}
