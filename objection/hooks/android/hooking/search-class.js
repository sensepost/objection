// Searches for a Java class containing a part of
// a string.

var search_string = '{{ search }}'.toLowerCase();

var classes = Java.enumerateLoadedClassesSync().filter(function (class_name) {

    if (class_name.toLowerCase().indexOf(search_string) != -1) {
        return class_name;
    }
});

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'android-class-search',
    data: classes
};

send(response);
