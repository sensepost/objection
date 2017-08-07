/**
 * @summary Lists the registered BroadcastReceivers
 * @author Bernard Wagner (@_dotvader)
 */


var BroadcastReceiver = Java.use('android.content.BroadcastReceiver');
var ActivityThread = Java.use('android.app.ActivityThread');
var ArrayMap = Java.use("android.util.ArrayMap");

var currentApplication = ActivityThread.currentApplication();
var context = currentApplication.getApplicationContext();

var receivers = []

currentApplication.mLoadedApk['value'].mReceivers['value'].values().toArray().map(function(arrayMap){
    Java.cast(arrayMap,ArrayMap).keySet().toArray().map(function(receiver){
        receivers.push(receiver.$className)
    });
});

receivers = receivers.concat(context.getPackageManager().getPackageInfo(context.getPackageName(), 0x00000002).receivers['value'].map(function (activity_info) {
    return activity_info.name['value'];
}));

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'android-broadcast-receivers',
    data: receivers
}

send(JSON.stringify(response));

