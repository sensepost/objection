// Attempts to find a method, and set its return value.

var target_class = Java.use('{{ class_name }}');

send({
    status: 'success',
    error_reason: NaN,
    type: 'set-return-value',
    data: 'Found instance of: {{ class_name }}. Hooking {{ method_name }}...'
});

eval('target_class.{{ method_name }}').implementation = function () {

    send({
        status: 'success',
        error_reason: NaN,
        type: 'set-return-value',
        data: 'Response to {{ class_name }}.{{ method_name }} set to {{ retval }}'
    });

    return '{{ retval }}' == 'True' ? true : false
};
