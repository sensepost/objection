var File = Java.use('java.io.File');
var String = Java.use('java.lang.String');

// get a string of the path to work with
var path = String.$new('{{ path }}');

// init a File object with the directory in question
var directory = File.$new(path);

// get a listing of the files in the directory
var files = directory.listFiles();

// check read / write access on the current path
var readable = directory.canRead();
var writable = directory.canWrite();

// variable for file information
var data = {
    path: '{{ path }}',
    readable: Boolean(readable),
    writable: Boolean(writable),
    files: {}
};

// if we can read the directory, process the files.
if (Boolean(readable)) {

    for (var i = 0; i < files.length; i++) {

        // reference a specific file. This will be an instance
        // of java.io.File already
        var file = files[i];

        data.files[file.getName()] = {
            fileName: file.getName(),
            readable: file.canRead(),
            writable: file.canWrite(),
            attributes: {
                isDirectory: file.isDirectory(),
                isFile: file.isFile(),
                isHidden: file.isHidden(),
                lastModified: file.lastModified(),
                size: file.length()
            }
        };
    }
}

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'list-directory-contents',
    data: data
};

send(response);

// -- Sample Java Code
//
// File d = new File(".");
// File[] files = d.listFiles();
// Log.e(getClass().getName(), "Files: " + files.length);

// for (int i = 0; i < files.length; i++) {

//     Log.e(getClass().getName(),
//             files[i].getName() + ": " + files[i].canRead()
//             + " " + files[i].lastModified()
//             + " " + files[i].length()
//     );

// }
