// Lists the registered broadcast receivers from android.app.LoadedApk
// as well as the android packageManager.

var ActivityThread = Java.use('android.app.ActivityThread');
var ArrayMap = Java.use('android.util.ArrayMap');
var PackageManager = Java.use('android.content.pm.PackageManager');

var GET_RECEIVERS = PackageManager.GET_RECEIVERS.value;

var currentApplication = ActivityThread.currentApplication();
var context = currentApplication.getApplicationContext();

var receivers = [];

currentApplication.mLoadedApk['value'].mReceivers['value'].values().toArray().map(function (arrayMap) {

    Java.cast(arrayMap, ArrayMap).keySet().toArray().map(function (receiver) {

        receivers.push(receiver.$className)
    });
});

receivers = receivers.concat(context.getPackageManager()
    .getPackageInfo(context.getPackageName(), GET_RECEIVERS).receivers['value'].map(function (activity_info) {

        return activity_info.name['value'];
    })
);

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'android-broadcast-receivers',
    data: receivers
};

send(response);
