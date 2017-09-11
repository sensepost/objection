// Downloads a file off the Android filesystem.
// This method is unbelievably slow :(
//
// TODO: Fix this slow thing asap!

var File = Java.use('java.io.File');
var FileInputStream = Java.use('java.io.FileInputStream');
var ByteArrayOutputStream = Java.use('java.io.ByteArrayOutputStream');

var file = File.$new('{{ path }}');
var file_length = parseInt(file.length());

var file_input_stream = FileInputStream.$new(file);
var bytes = ByteArrayOutputStream.$new(parseInt(file_length)).toByteArray();

// Method that is run when the 'download' method is called.
var populate_bytes = function () {

    // console.log('Reading ' + file_length + ' bytes...');
    for (var i = 0; i < file.length(); i++) {

        // Cause this is sooooo slowwwwwww, progress report
        // on the download.
        if (i % 10000 == 0) {

            var progress = i / file_length * 100;

            if (progress > 0) {

                console.log('Progress: ' + parseFloat(progress).toFixed(3) + ' %');
            }
        }

        // Update the byte we have read.
        bytes[i] = file_input_stream.read();
    }
};

rpc.exports = {
    download: function () {

        Java.perform(function () { populate_bytes(); });

        return bytes;
    }
};

// -- Sample Java
//
// File f = new File("/etc/system_fonts.xml");
// FileInputStream fis = new FileInputStream(f);
// for (int i=0; i < f.length(); i++) {
//     Log.e("byte", "byte: " + i + " " + fis.read());
// }
