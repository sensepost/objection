// Determines the current working directory, based
// on the main bundles path on the iOS device.

var NSBundle = ObjC.classes.NSBundle;
var BundleURL = NSBundle.mainBundle().bundlePath();

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'current-working-directory',
    data: {
        cwd: String(BundleURL)
    }
};

send(response);

// -- Sample Objective-C
//
// NSURL *bundleURL = [[NSBundle mainBundle] bundleURL];
