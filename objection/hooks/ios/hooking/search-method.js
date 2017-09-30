// Searches for an objective-c methods containing a part of
// a string.

var methods = [];
var search_string = '{{ search }}'.toLowerCase();

// Loop all classes
for (var class_name in ObjC.classes) {

    // Grab the methods in this class
    var class_methods = eval('ObjC.classes.' + class_name + '.$ownMethods');

    // Loop the methods we found in the class
    for (var i = 0; i < class_methods.length; i++) {

        var method = class_methods[i];

        // If the method we got  matches the search string, add
        // it to the response methods array.
        if (method.toLowerCase().indexOf(search_string) != -1) {

            methods.push('[' + class_name + ' ' + method + ']');
        }
    }
}

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'ios-method-search',
    data: methods
};

send(response);
