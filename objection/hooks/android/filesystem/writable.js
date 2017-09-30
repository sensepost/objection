// Determines if a path on the Android device is writable.

var File = Java.use('java.io.File');
var file = File.$new('{{ path }}');

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'file-writable',
    data: {
        path: '{{ path }}',
        writable: Boolean(file.canWrite())
    }
};

send(response);

// -- Sample Java Code
//
// File d = new File(".");
// d.canWrite();
