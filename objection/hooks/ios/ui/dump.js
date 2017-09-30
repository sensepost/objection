// Dumps the current window in a serialized form.

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'ios-ui-dump',
    data: ObjC.classes.UIWindow.keyWindow().recursiveDescription().toString()
};

send(response);
