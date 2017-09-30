// Attempts to disable root detection.
// Again, a weird thing considering what objection tries to do,
// but there may be cases where this makes sense.

var String = Java.use('java.lang.String');
var Runtime = Java.use('java.lang.Runtime');
var IOException = Java.use('java.io.IOException');
var File = Java.use('java.io.File');

// Get the common_paths for Android
//jinja: include 'android/root/_common_paths.js'

// 'test-keys' check.
String.contains.implementation = function (check) {

    if (check == 'test-keys') {

        send({
            status: 'success',
            error_reason: NaN,
            type: 'root-bypass',
            data: 'Check for test-keys was detected. Marking it as failed.'
        });

        return false;
    }

    // call the original method
    this.contains.apply(this, arguments);
};

// exec check for su command.
Runtime.exec.overload('java.lang.String').implementation = function (command) {

    if (command.endsWith('su')) {

        send({
            status: 'success',
            error_reason: NaN,
            type: 'root-bypass',
            data: 'Check for su detected with command \'' + command + '\'. Throwing an IOException.'
        });

        throw IOException.$new('anti-root');
    }

    // call the original method
    this.contains.apply(this, arguments);
};

// file existence checks.
File.exists.implementation = function () {

    // grab the filename we are working with
    var filename = this.getAbsolutePath();

    // check if the looked up path is in the list of common_paths
    if (common_paths.indexOf(filename) >= 0) {

        send({
            status: 'success',
            error_reason: NaN,
            type: 'root-bypass',
            data: 'Check for \'' + filename + '\' was detected. Returning false.'
        });

        return false
    }

    // call the original method
    this.contains.apply(this, arguments);
};
