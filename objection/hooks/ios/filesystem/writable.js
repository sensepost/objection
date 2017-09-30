// Determines if a path on the iOS device is writable.

var NSFileManager = ObjC.classes.NSFileManager;
var NSString = ObjC.classes.NSString;

// get a file manager instance
var fm = NSFileManager.defaultManager();

// init the path we want to check
var path = NSString.stringWithString_('{{ path }}');
var writable = fm.isWritableFileAtPath_(path);

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'file-writable',
    data: {
        path: '{{ path }}',
        writable: Boolean(writable)
    }
};

send(response);

// -- Sample Objective-C
//
// NSFileManager *fm = [NSFileManager defaultManager];
// NSLog(@"%d / readable?", [fm isReadableFileAtPath:@"/"]);
