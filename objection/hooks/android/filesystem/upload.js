// Uploads a file to the remote Android devices filesystem.
// The file contents itself is a base64 encoded string. This might
// not be the best implementation from a performance perspective.

var File = Java.use('java.io.File');
var FileOutputStream = Java.use('java.io.FileOutputStream');
var Base64 = Java.use('android.util.Base64');

var file = File.$new('{{ destination }}');
var decoded_bytes = Base64.decode('{{ base64_data }}', 0);

// check that the file exists, else create it
if (!file.exists()) {

    file.createNewFile();
}

// Write the data!
var fos = FileOutputStream.$new(file.getAbsolutePath());
fos.write(decoded_bytes, 0, decoded_bytes.length);
fos.close();

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'file-upload',
    data: 'File written to: ' + file.getAbsolutePath()
};

// send the response message
send(response);

// -- Sample Java
//
// try {
//     byte[] f = Base64.decode("MTI3LjAuMC4xICAgICAgIGxvY2FsaG9zdAo6OjEgICAgICAgICAgICAgaXA2LWxvY2FsaG9zdAo=", Base64.DEFAULT);
//
//     File file = new File(getCacheDir() + "/hosts");
//
//     if (! file.exists()) {
//         Log.e("file", "creating file");
//         file.createNewFile();
//     }
//
//     Log.e("file", "writing file");
//     FileOutputStream fos = new FileOutputStream(file.getAbsolutePath());
//     fos.write(f);
//     fos.close();
//
// } catch (Exception e) {
//
// }
