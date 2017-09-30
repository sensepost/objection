// Watches for all method invocations of a certain Objective-C
// class. Based on the value of the include_parents Jinja template
// variable, the class in questions parent methods may also be
// hooked.

for (var class_name in ObjC.classes) {

    if (class_name == '{{ class_name }}') {

        send({
            status: 'success',
            error_reason: NaN,
            type: 'call-to-hooked-method',
            data: 'Found class: {{ class_name }}, hooking methods...'
        });

        // if we should include parent classes, do that.
        if ('{{ include_parents }}' == 'True') {

            var methods = eval('ObjC.classes.{{ class_name }}.$methods');

        } else {

            var methods = eval('ObjC.classes.{{ class_name }}.$ownMethods');

        }

        // hook into all of the methods in this class
        for (var i = 0; i < methods.length; i++) {

            // the current method
            var method = methods[i];

            var selector = eval('ObjC.classes.{{ class_name }}["' + method + '"]');

            try {
                // attach an interceptor
                Interceptor.attach(selector.implementation, {
                    onEnter: function (args) {

                        var receiver = new ObjC.Object(args[0]);
                        var message = '(Kind: ' + receiver.$kind +
                            ') (Super: ' + receiver.$superClass +
                            ') [' + receiver.$className + ' ' + ObjC.selectorAsString(args[1]) + ']';

                        send({
                            status: 'success',
                            error_reason: NaN,
                            type: 'call-to-hooked-method',
                            data: 'Hit: ' + message
                        });
                    }
                });
            } catch (err) {

                send({
                    status: 'success',
                    error_reason: 'Hooking method ' + method + 'failed with: ' + err.message,
                    type: 'call-to-hooked-method',
                    data: NaN
                });
            }
        }
    }
}
