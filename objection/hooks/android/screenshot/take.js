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

var data;

var populate_bytes = function () {
    var activityThread = ActivityThread.currentActivityThread();
    var currentApplication = ActivityThread.currentApplication();
    var context = currentApplication.getApplicationContext();
    var t0 = new Date().getTime();
    var activityRecords = activityThread.mActivities['value'].values().toArray();

    var currentActivity;

    for (var i in activityRecords){
        var activityRecord =  Java.cast(activityRecords[i],ActivityClientRecord);
        if (!activityRecord.paused['value']){
            currentActivity = Java.cast(Java.cast(activityRecord,ActivityClientRecord).activity['value'],Activity);
            break;
        }
    }

    if (currentActivity){
        var view = currentActivity.getWindow().getDecorView().getRootView();
        view.setDrawingCacheEnabled(true);
        var bitmap = Bitmap.createBitmap(view.getDrawingCache());
        view.setDrawingCacheEnabled(false);
        var outputStream = ByteArrayOutputStream.$new();
        bitmap.compress(CompressFormat.PNG['value'],100,outputStream); 
        bytes = outputStream.buf['value'];
    } 
}

rpc.exports = {
    screenshot: function () {
        Java.perform(function () { populate_bytes(); });
        return bytes;
    },
};
