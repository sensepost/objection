// NSFileManager *fm = [NSFileManager defaultManager];
// if ([fm fileExistsAtPath:@"/"]) {
//     NSLog(@"Yep!");
// }

var NSFileManager = ObjC.classes.NSFileManager;
var NSString = ObjC.classes.NSString;

// get a file manager instance and list the files in the path
var fm = NSFileManager.defaultManager();

// init the path we want to check
var path = NSString.stringWithString_("{{ path }}");
var exists = fm.fileExistsAtPath_(path);

var response = {
    status: "success",
    error_reason: NaN,
    type: "file-exists",
    data: {
        path: "{{ path }}",
        exists: Boolean(exists)
    }
}

send(JSON.stringify(response));
