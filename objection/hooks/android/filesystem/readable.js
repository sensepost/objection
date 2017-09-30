// Checks if a path is readable
var File = Java.use('java.io.File');
var file = File.$new('{{ path }}');

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'file-readable',
    data: {
        path: '{{ path }}',
        readable: Boolean(file.canRead())
    }
};

send(response);

// -- Sample Java Code
//
// File d = new File(".");
// d.canRead();
