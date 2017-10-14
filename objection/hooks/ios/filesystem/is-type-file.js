// hacky way to check if a path is a file. Using the nice class
// fileExiststAtPath:isDirectory: method in a NSFileManager is a hard
// convert to Frida due to the pointer needed to flag isDirectory:

// so, here is a workaround reading the attributes of the file :D

// TODO: Don't be dumb. We can init the pointer we need with Memory.alloc(Process.pointerSize);

var NSFileManager = ObjC.classes.NSFileManager;
var NSString = ObjC.classes.NSString;

// get a file manager instance to work with
var fm = NSFileManager.defaultManager();

// init the path we want to test
var path = NSString.stringWithString_('{{ path }}');

// get the attributes for the pathed item
var attributes = fm.attributesOfItemAtPath_error_(path, NULL);

// prep the response array with some default values. we assume
// failure.
var response = {
    status: 'failure',
    error_reason: 'Not a file or could not read attributes',
    type: 'is-type-file',
    data: {
        path: '{{ path }}',
        is_file: false
    }
};

// if we were able to get attributes for the path, try and
// read the NSFileType key 
if (attributes) {

    var path_type = attributes.objectForKey_('NSFileType');

    if (path_type == 'NSFileTypeRegular') {

        response.status = 'success';
        response.error_reason = NaN;
        response.data.is_file = true
    }
}

send(response);
