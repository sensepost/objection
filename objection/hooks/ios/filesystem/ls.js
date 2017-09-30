// Obtains a directory listing for a specified path.

var NSFileManager = ObjC.classes.NSFileManager;
var NSString = ObjC.classes.NSString;

// get a file manager instance to work with
var fm = NSFileManager.defaultManager();

// init the path we want to list
var path = NSString.stringWithString_('{{ path }}');

// check read / write access on the current path
var readable = fm.isReadableFileAtPath_(path);
var writable = fm.isWritableFileAtPath_(path);

// variable for file information
var data = {
    path: '{{ path }}',
    readable: Boolean(readable),
    writable: Boolean(writable),
    files: {}
};

var perform_ls = function () {

    // If this directory is not readable, stop.
    if (!Boolean(readable)) {
        return;
    }

    // get the directory listing
    var contents = fm.contentsOfDirectoryAtPath_error_(path, NULL);

    // file count
    var count = contents.count();

    // loop-de-loop files
    for (var i = 0; i < count; i++) {

        // pick a file off contents
        var file = contents.objectAtIndex_(i);

        var file_data = {
            fileName: file.toString(),
            readable: NaN,
            writable: NaN,
            attributes: {}
        };

        // generate a full path to the file
        var item_path = NSString.stringWithString_(path + '/' + file);

        // check read / write
        file_data.readable = fm.isReadableFileAtPath_(item_path);
        file_data.writable = fm.isWritableFileAtPath_(item_path);

        // get attributes
        var attributes = fm.attributesOfItemAtPath_error_(item_path, NULL);

        // if we were able to get attributes for the item,
        // append them to those for this file. (example is listing
        // files in / have some that cant have attributes read for :|)
        if (attributes) {

            // loop the attributes and set them in the file_data
            // dictionary
            var enumerator = attributes.keyEnumerator();
            var key;
            while ((key = enumerator.nextObject()) !== null) {

                // get attribute data
                var value = attributes.objectForKey_(key);
                // add it to the attributes for this item
                file_data.attributes[key] = value.toString();
            }
        }

        // finally, add the file to the final response
        data.files[file] = file_data;
    }
};

rpc.exports = {
    ls: function () {

        perform_ls();

        return data;
    }
};

// -- Sample Objective-C
//
// NSFileManager *fm = [NSFileManager defaultManager];
// NSString *bundleURL = [[NSBundle mainBundle] bundlePath];
// NSArray *contents = [fm contentsOfDirectoryAtPath:bundleURL error:nil];

// for (id item in contents) {
//     NSString *p = [[NSString alloc] initWithFormat:@"%@/%@",bundleURL, item];
//     NSDictionary *attribs = [fm attributesOfItemAtPath:p error:nil];
//     NSLog(@"%@ - %@", p, attribs);
// }
