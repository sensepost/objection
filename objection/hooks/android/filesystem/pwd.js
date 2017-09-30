// Determines the current working directory, based
// on the applications filesDir

var ActivityThread = Java.use('android.app.ActivityThread');

var currentApplication = ActivityThread.currentApplication();
var context = currentApplication.getApplicationContext();

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'current-working-directory',
    data: {
        cwd: context.getFilesDir().getAbsolutePath().toString()
    }
};

send(response);

// -- Sample Java
//
// getApplicationContext().getFilesDir().getAbsolutePath()
