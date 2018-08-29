import unittest

from objection.utils.templates import _get_name_with_js_suffix, generic_hook, ios_hook, android_hook


class TestTemplates(unittest.TestCase):
    def test_gets_hook_name_and_adds_js_prefix(self):
        result = _get_name_with_js_suffix('foo')

        self.assertEqual(result, 'foo.js')

    def test_gets_hook_name_and_does_not_add_js_prefix_if_exists(self):
        result = _get_name_with_js_suffix('foo.js')

        self.assertEqual(result, 'foo.js')

    def test_finds_and_compiles_generic_hooks_with_an_exception_handler(self):
        hook = generic_hook('memory/write')

        expected_output = """try {

    // Writes arbitrary bytes to a memory address.

var bar = eval(['{{ pattern }}']);

Memory.writeByteArray(ptr('{{ destination }}'), bar);


} catch (err) {

    var response = {
        status: 'error',
        error_reason: err.message,
        type: 'global-exception',
        data: {}
    };

    send(response);
}
"""

        self.assertEqual(hook, expected_output)

    def test_finds_and_compiles_generic_hooks_without_an_exception_handler(self):
        hook = generic_hook('memory/write', skip_trycarch=True)

        expected_output = """// Writes arbitrary bytes to a memory address.

var bar = eval(['{{ pattern }}']);

Memory.writeByteArray(ptr('{{ destination }}'), bar);
"""

        self.assertEqual(hook, expected_output)

    def test_finds_and_compiles_ios_hooks_with_an_exception_handler(self):
        hook = ios_hook('filesystem/pwd')

        expected_output = """if (ObjC.available) {

    try {

        // Determines the current working directory, based
// on the main bundles path on the iOS device.

var NSBundle = ObjC.classes.NSBundle;
var BundleURL = NSBundle.mainBundle().bundlePath();

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'current-working-directory',
    data: {
        cwd: BundleURL.toString()
    }
};

send(response);

// -- Sample Objective-C
//
// NSURL *bundleURL = [[NSBundle mainBundle] bundleURL];


    } catch (err) {

        var response = {
            status: 'error',
            error_reason: err.message,
            type: 'global-exception',
            data: {}
        };

        send(response);
    }

} else {

    var response = {
        status: 'error',
        error_reason: 'Objective-C runtime is not available.',
        type: 'global-exception',
        data: {}
    };

    send(response);
}
"""

        self.assertEqual(hook, expected_output)

    def test_finds_and_compiles_ios_hooks_without_an_exception_handler(self):
        hook = ios_hook('filesystem/pwd', skip_trycatch=True)

        expected_output = """// Determines the current working directory, based
// on the main bundles path on the iOS device.

var NSBundle = ObjC.classes.NSBundle;
var BundleURL = NSBundle.mainBundle().bundlePath();

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'current-working-directory',
    data: {
        cwd: BundleURL.toString()
    }
};

send(response);

// -- Sample Objective-C
//
// NSURL *bundleURL = [[NSBundle mainBundle] bundleURL];
"""

        self.assertEqual(hook, expected_output)

    def test_finds_and_compiles_android_hooks_with_an_exception_handler(self):
        hook = android_hook('filesystem/pwd')

        expected_output = """if (Java.available) {

    try {

        // From Frida documentation:
        //  "ensure that the current thread is attached to the VM and call fn"
        //
        // We also handle the exception that could happen within the callback as
        // it does not seem to bubble outside of it.
        Java.perform(function () {

            try {

                // Determines the current working directory, based
// on the applications filesDir

var ActivityThread = Java.use('android.app.ActivityThread');

var currentApplication = ActivityThread.currentApplication();
var context = currentApplication.getApplicationContext();

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'current-working-directory',
    data: {
        cwd: context.getFilesDir().getAbsolutePath().toString()
    }
};

send(response);

// -- Sample Java
//
// getApplicationContext().getFilesDir().getAbsolutePath()


            } catch (err) {

                var response = {
                    status: 'error',
                    error_reason: err.message,
                    type: 'java-perform-exception',
                    data: {}
                };

                send(response);
            }
        });

    } catch (err) {

        var response = {
            status: 'error',
            error_reason: err.message,
            type: 'global-exception',
            data: {}
        };

        send(response);
    }

} else {

    var response = {
        status: 'error',
        error_reason: 'Java runtime is not available.',
        type: 'global-exception',
        data: {}
    };

    send(response);
}
"""
        self.assertEqual(hook, expected_output)

    def test_finds_and_compiles_android_hooks_without_an_exception_handler(self):
        hook = android_hook('filesystem/pwd', skip_trycatch=True)

        expected_output = """// Determines the current working directory, based
// on the applications filesDir

var ActivityThread = Java.use('android.app.ActivityThread');

var currentApplication = ActivityThread.currentApplication();
var context = currentApplication.getApplicationContext();

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'current-working-directory',
    data: {
        cwd: context.getFilesDir().getAbsolutePath().toString()
    }
};

send(response);

// -- Sample Java
//
// getApplicationContext().getFilesDir().getAbsolutePath()
"""

        self.assertEqual(hook, expected_output)
