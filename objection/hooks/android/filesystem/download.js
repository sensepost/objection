// Downloads a file off the Android filesystem.
// This method is unbelievably slow :(
//
// TODO: Fix this slow thing asap!

var File = Java.use('java.io.File');
var Files = Java.use('java.nio.file.Files');
var Base64 = Java.use('android.util.Base64');
var ByteArrayOutputStream = Java.use('java.io.ByteArrayOutputStream');

var file = File.$new('{{ path }}');
var file_length = parseInt(file.length());

var bytes = ByteArrayOutputStream.$new(parseInt(file_length)).toByteArray();

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'file-download',
    data: Base64.encodeToString(Files.readAllBytes(file.toPath()), 0)
};

// send the response message
send(response);

// -- Sample Java
//
// File f = new File("/etc/system_fonts.xml");
// FileInputStream fis = new FileInputStream(f);
// for (int i=0; i < f.length(); i++) {
//     Log.e("byte", "byte: " + i + " " + fis.read());
// }
