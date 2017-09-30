// Gets the declared methods for a Java class.

var class_name = Java.use('{{ class_name }}');

var methods = class_name.class.getDeclaredMethods().map(function(method) {

    return  method.toGenericString();
});

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'android-class-methods',
    data: methods
};

send(response);
