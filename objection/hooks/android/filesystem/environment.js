var ActivityThread = Java.use('android.app.ActivityThread');

var currentApplication = ActivityThread.currentApplication();
var context = currentApplication.getApplicationContext();

var data = {

    filesDirectory: context.getFilesDir().getAbsolutePath().toString(),
    cacheDirectory: context.getCacheDir().getAbsolutePath().toString(),
    externalCacheDirectory: context.getExternalCacheDir().getAbsolutePath().toString(),
    codeCacheDirectory: context.getCodeCacheDir().getAbsolutePath().toString(),
    obbDir: context.getObbDir().getAbsolutePath().toString(),
    packageCodePath: context.getPackageCodePath().toString()
};

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'environment-directories',
    data: data 
};

send(response);

// -- Sample Java
//
// getApplicationContext().getFilesDir().getAbsolutePath()
