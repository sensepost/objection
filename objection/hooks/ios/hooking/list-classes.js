// Lists the classes available in the current Objective-C
// runtime.

var classes = [];

for (var class_name in ObjC.classes) {
    classes.push(class_name);
}

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'ios-classes',
    data: classes
};

send(response);
