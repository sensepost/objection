// Lists the loaded classes that extend BroadcastReceiver available in the current Java
// runtime.

var BroadcastReceiver = Java.use("android.content.BroadcastReceiver")
var ActivityThread = Java.use('android.app.ActivityThread');

var currentApplication = ActivityThread.currentApplication();
var context = currentApplication.getApplicationContext();

var classes = Java.enumerateLoadedClassesSync()

var receivers = classes.filter(function(className){
    //Exclude some classes to prevent Java.use blocking (Some memory management issue)
    if (className.startsWith("android") || className.startsWith("java") || className.startsWith("com.android") || !className.includes(".")) return false;

    //Some classes are not in search path resulting in Java.use throwing exception
    try{
        var clazz = Java.use(className);
        var isReceiver = BroadcastReceiver.class.isAssignableFrom(clazz.class);
        clazz.$dispose();
        return isReceiver;
    } catch (e){}
    return false;
})

receivers = receivers.concat(context.getPackageManager().getPackageInfo(context.getPackageName(),0x00000002).receivers['value'].map(function(activity_info){
    return activity_info.name['value'];
}))



var response = {
    status: 'success',
    error_reason: NaN,
    type: 'android-broadcast-receivers',
    data: receivers
}

send(JSON.stringify(response));

