// Watches a Java class method and dumps the calling arguments.
// All of the matching overloads of the method in question
// is also watched.

var target_class = Java.use('{{ target_class }}');
var overload_count = eval('target_class.{{ target_method }}.overloads.length');

send({
    status: 'success',
    error_reason: NaN,
    type: 'java-argument-dump',
    data: 'Found class with ' + overload_count + ' overloads for {{ target_method }}'
});

// Hook all of the overloads found for this class.method
for (var i = 0; i < overload_count; i++) {

    send({
        status: 'success',
        error_reason: NaN,
        type: 'java-argument-dump',
        data: 'Hooking overload ' + (i + 1)
    });

    // Hook the overload.
    eval('target_class.{{ target_method }}.overloads[i]').implementation = function () {

        send({
            status: 'success',
            error_reason: NaN,
            type: 'java-argument-dump',
            data: 'Called {{ target_class }}.{{ target_method }} (args: ' + arguments.length + ')'
        });

        // Loop the arguments and dump the values.toString()
        for (var h = 0; h < arguments.length; h++) {

            send({
                status: 'success',
                error_reason: NaN,
                type: 'java-argument-dump',
                data: '{{ target_method }} - Arg ' + h + ': ' + arguments[h].toString()
            });
        }

        // continue with the original method
        return eval('this.{{ target_method }}.apply(this, arguments)');
    }
}
