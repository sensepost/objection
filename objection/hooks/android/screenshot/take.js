var WindowManager = Java.use("android.view.WindowManager");
var ActivityThread = Java.use('android.app.ActivityThread');
var Activity = Java.use("android.app.Activity");
var ActivityClientRecord = Java.use("android.app.ActivityThread$ActivityClientRecord");
var ArrayMap = Java.use('android.util.ArrayMap');
var Bitmap = Java.use("android.graphics.Bitmap");
var File = Java.use("java.io.File");
var ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
var CompressFormat = Java.use("android.graphics.Bitmap$CompressFormat");
var Base64 = Java.use('android.util.Base64');

var activityThread = ActivityThread.currentActivityThread();
var currentApplication = ActivityThread.currentApplication();
var context = currentApplication.getApplicationContext();

var activityRecords = activityThread.mActivities['value'].values().toArray().filter(function(activityRecord) {
    return !Java.cast(activityRecord,ActivityClientRecord).paused['value'];
});

if (activityRecords.length > 0) {
    var currentActivity = Java.cast(Java.cast(activityRecords[0],ActivityClientRecord).activity['value'],Activity);

    if (currentActivity){
        var view = currentActivity.getWindow().getDecorView().getRootView();
        view.setDrawingCacheEnabled(true);
        var bitmap = Bitmap.createBitmap(view.getDrawingCache());
        view.setDrawingCacheEnabled(false);
        var outputStream = ByteArrayOutputStream.$new();
        bitmap.compress(CompressFormat.PNG['value'],100,outputStream); 
        send(JSON.stringify({
            status: 'success',
            error_reason: NaN,
            type: 'android-screenshot',
            data: Base64.encodeToString(outputStream.toByteArray(),0)
        }));      
        return;
    }
} else {
    send(JSON.stringify({
        status: 'error',
        error_reason: 'Could not find current Activity. Is the application in the foreground?',
        type: 'android-screenshot',
        data: NaN
    }));  
}


