// Downloads a file off the iOS devices filesystem.

var NSString = ObjC.classes.NSString;
var NSData = ObjC.classes.NSData;

// init the path we want to download
var path = NSString.stringWithString_('{{ path }}');

// 'download' data by reading it into an NSData object
var data = NSData.dataWithContentsOfFile_(path);

// convert the NSData to bytes we can push with send()
var bytes = Memory.readByteArray(data.bytes(), data.length());

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'file-download',
    data: {
        path: '{{ path }}'
    }
};

// send the response message and the bytes 'downloaded'
send(response, bytes);

// -- Sample Objective-C
//
// NSData *data = [NSData dataWithContentsOfFile:fileToRead];
