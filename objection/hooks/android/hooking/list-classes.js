// Lists the loaded classes available in the current Java
// runtime.

var classes = Java.enumerateLoadedClassesSync();

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'android-classes',
    data: classes
};

send(response);
