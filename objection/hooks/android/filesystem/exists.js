// Checks if a path exists on an Android filesystem.

var File = Java.use('java.io.File');
var String = Java.use('java.lang.String');

// get a string of the path to work with
var path = String.$new('{{ path }}');

// init a File object with the path in question
var directory = File.$new(path);

// check if the path exists
var exists = directory.exists();

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'file-exists',
    data: {
        path: '{{ path }}',
        exists: Boolean(exists)
    }
};

send(response);

// -- Sample Java
//
// File path = new File(".");
// Boolean e = path.exists();
