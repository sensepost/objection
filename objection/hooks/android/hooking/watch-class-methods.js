// Watches a Java class  and reports on method invocations.

var Throwable = Java.use('java.lang.Throwable');
var target_class = '{{ target_class }}'.toString();
var target_class_array = [];

var dump_args = ('{{ dump_args }}'.toLowerCase() === 'true');
var dump_return = ('{{ dump_return }}'.toLowerCase() === 'true');
var dump_backtrace = ('{{ dump_backtrace }}'.toLowerCase() === 'true');

if (target_class.indexOf("*") > -1){
    console.log("Searching for class pattern: "+target_class);
    // enumerate all classes and match against regex
    Java.enumerateLoadedClasses({
        onMatch: function(aClass) {
            if (aClass.match(target_class)) {
                target_class_array.push(aClass);
            }
        },
        onComplete: function() {}
    });
} else {
    target_class_array.push(target_class);
}

// Get the methods this class has and filter for unique ones.
for (var counter = 0; counter < target_class_array.length; counter++){
    var target_class_name = target_class_array[counter];
    var target_class = Java.use(target_class_name);

    send({
        status: 'success',
        error_reason: NaN,
        type: 'watch-class',
        data: 'Found class named ' + target_class_name
    });

var methods = target_class.class.getDeclaredMethods().map(function (method) {

    // eg: public void com.example.fooBar(int,int)
    var full_method_signature = method.toGenericString();

    // strip any 'throws' the method may have
    if (full_method_signature.indexOf(' throws ') !== -1) {
        full_method_signature = full_method_signature.substring(0, full_method_signature.indexOf(' throws '));
    }

    // remove the scope and return type
    var method_only_delimiter_location = full_method_signature.lastIndexOf(' ');
    var class_and_method_name = full_method_signature.slice(method_only_delimiter_location)

    // remove the classname
    var method_name_with_signature = class_and_method_name.replace(' ' + '{{ target_class }}' + '.', '');
    // remove the signature
    var method_name_only = method_name_with_signature.split('(')[0].split('.');
    return method_name_only[method_name_only.length-1];

}).filter(function (value, index, self) {

    // filter to unique values only
    return self.indexOf(value) === index;
});

send({
    status: 'success',
    error_reason: NaN,
    type: 'watch-class',
    data: 'Found class with ' + methods.length + ' methods (excl: overloads)',
});

methods.map(function (method) {

    var overload_count = target_class[method] ? target_class[method].overloads.length : 0;

    // Hook all of the overloads found for this class.method
    // TODO: Make this a function that can be used in both this class
    // watcher as well as the specific method watcher. Or, simply
    // change the command to optionally specify a specific method.
    for (var i = 0; i < overload_count; i++) {

        send({
            status: 'success',
            error_reason: NaN,
            type: 'watch-class',
            data: 'Hooking overload: ' + (i + 1) + ' for ' + method
        });

        // Hook the overload.
        target_class[method].overloads[i].implementation = function () {

            var message = 'Called ' + target_class + '.' + method + ' (args: ' + arguments.length + ')';

            // if we should include a backtrace to here, do that.
            if (dump_backtrace) {

                message += '\nBacktrace:\n\t' + Throwable.$new().getStackTrace()

                    .map(function (stack_trace_element) {

                        return stack_trace_element.toString() + '\n\t';
                    }).join('');
            }

            send({
                status: 'success',
                error_reason: NaN,
                type: 'watch-class',
                data: message
            });

            if (dump_args) {

                // Loop the arguments and dump the values.toString()
                for (var h = 0; h < arguments.length; h++) {

                    send({
                        status: 'success',
                        error_reason: NaN,
                        type: 'watch-class',
                        data: method + ' - Arg ' + h + ': ' + (arguments[h] || '(none)').toString()
                    });
                }
            }

            // continue with the original method and capture the return value
            var return_value = this[method].apply(this, arguments);

            if (dump_return) {

                send({
                    status: 'success',
                    error_reason: NaN,
                    type: 'watch-class',
                    data: method + ' - Returned : ' + (return_value || '(none)').toString()
                });
            }

            // finally, return
            return return_value;
        }
    }
});

};
