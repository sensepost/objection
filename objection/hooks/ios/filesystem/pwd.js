// NSURL *bundleURL = [[NSBundle mainBundle] bundleURL];

var NSBundle = ObjC.classes.NSBundle;
var BundleURL = NSBundle.mainBundle().bundlePath();

var response = {
    status: "success",
    error_reason: NaN,
    type: "current-working-directory",
    data: {
        cwd: String(BundleURL),
    }
}

send(JSON.stringify(response));
