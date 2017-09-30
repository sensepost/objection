// Searches for an objective-c class containing a part of
// a string.

var classes = [];
var search_string = '{{ search }}'.toLowerCase();

for (var class_name in ObjC.classes) {

    if (class_name.toLowerCase().indexOf(search_string) != -1) {

        classes.push(class_name);
    }
}

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'ios-class-search',
    data: classes
};

send(response);
