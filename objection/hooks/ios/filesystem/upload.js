// Uploads a file to the remote iOS devices filesystem.
// The file contents itself is a base64 encoded string. This might
// not be the best implementation from a performance perspective.

var NSFileManager = ObjC.classes.NSFileManager;
var NSString = ObjC.classes.NSString;
var NSData = ObjC.classes.NSData;

// get a file manager instance to work with
var fm = NSFileManager.defaultManager();

// init the path and data to write
var destination = NSString.stringWithString_('{{ destination }}');
var data = NSData.alloc().initWithBase64EncodedString_options_('{{ base64_data }}', 0);

// write the data
fm.createFileAtPath_contents_attributes_(destination, data, NULL);

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'file-upload',
    data: 'File written to: ' + destination
};

// send the response message
send(response);

// -- Sample Objective-C
//
// NSFileManager *fm = [NSFileManager defaultManager];
// NSString *documents = [[[fm URLsForDirectory:NSDocumentDirectory inDomains:NSUserDomainMask] lastObject] path];
// NSData *data = [[NSData alloc] initWithBase64EncodedString:@"E=" options:0];
// NSString *destination = [[NSString alloc] initWithFormat:@"%@/%@", documents, @"test.txt"];

// [fm createFileAtPath:destination contents:data attributes:nil];
