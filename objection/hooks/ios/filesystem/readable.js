// Determine if a file is readable on the iOS filesystem.

var NSFileManager = ObjC.classes.NSFileManager;
var NSString = ObjC.classes.NSString;

// get a file manager instance
var fm = NSFileManager.defaultManager();

// init the path we want to check
var path = NSString.stringWithString_('{{ path }}');
var readable = fm.isReadableFileAtPath_(path);

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'file-readable',
    data: {
        path: '{{ path }}',
        readable: Boolean(readable)
    }
};

send(response);

// -- Sample Objective-C
//
// NSFileManager *fm = [NSFileManager defaultManager];
// NSLog(@"%d / readable?", [fm isReadableFileAtPath:@"/"]);
