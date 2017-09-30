// Sets the FLAG_SECURE FLAG for the current activity.
const VALUE = eval('{{ value }}');

const FLAG_SECURE = 0x00002000;

const ActivityThread = Java.use('android.app.ActivityThread');
const Activity = Java.use('android.app.Activity');
const ActivityClientRecord = Java.use('android.app.ActivityThread$ActivityClientRecord');

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

    // Somehow the next line prevents Frida from throwing an abort error
    currentActivity.getWindow();

    // Set flag and trigger update (Throws abort without first calling getWindow())
    Java.scheduleOnMainThread(function () {

        currentActivity.getWindow().setFlags(VALUE ? FLAG_SECURE : 0, FLAG_SECURE);
    });

    send({
        status: 'success',
        error_reason: NaN,
        type: 'android-flag-secure',
        data: VALUE
    });
}
