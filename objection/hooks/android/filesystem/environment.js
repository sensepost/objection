var currentApplication = Java.use('android.app.ActivityThread').currentApplication(); 
var context = currentApplication.getApplicationContext();

var data = {

    filesDirectory: context.getFilesDir().getAbsolutePath().toString(),
    cacheDirectory: context.getCacheDir().getAbsolutePath().toString(),
    codeCacheDirectory: context.getCodeCacheDir().getAbsolutePath().toString(),
}

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'environment-directories',
    data: data 
}

send(JSON.stringify(response));

// -- Sample Java
//
// getApplicationContext().getFilesDir().getAbsolutePath()
