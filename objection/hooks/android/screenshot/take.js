// Take a screenshot by making use of a View's drawing cache:
//  ref: https://developer.android.com/reference/android/view/View.html#getDrawingCache(boolean)

var ActivityThread = Java.use('android.app.ActivityThread');
var Activity = Java.use('android.app.Activity');
var ActivityClientRecord = Java.use('android.app.ActivityThread$ActivityClientRecord');
var Bitmap = Java.use('android.graphics.Bitmap');
var ByteArrayOutputStream = Java.use('java.io.ByteArrayOutputStream');
var CompressFormat = Java.use('android.graphics.Bitmap$CompressFormat');

var bytes;

var populate_bytes = function () {

    var activityThread = ActivityThread.currentActivityThread();
    var activityRecords = activityThread.mActivities['value'].values().toArray();

    var currentActivity;

    for (var i in activityRecords) {

        var activityRecord = Java.cast(activityRecords[i], ActivityClientRecord);

        if (!activityRecord.paused['value']) {
            currentActivity = Java.cast(Java.cast(activityRecord, ActivityClientRecord)
                .activity['value'], Activity);

            break;
        }
    }

    if (currentActivity) {

        var view = currentActivity.getWindow().getDecorView().getRootView();
        view.setDrawingCacheEnabled(true);
        var bitmap = Bitmap.createBitmap(view.getDrawingCache());
        view.setDrawingCacheEnabled(false);

        var outputStream = ByteArrayOutputStream.$new();
        bitmap.compress(CompressFormat.PNG['value'], 100, outputStream);
        bytes = outputStream.buf['value'];
    }
};

rpc.exports = {
    screenshot: function () {

        Java.perform(function () { populate_bytes(); });
        return bytes;
    }
};
