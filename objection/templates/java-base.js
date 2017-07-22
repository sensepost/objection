if (Java.available) {

    try {

        // From Frida documentation:
        //  "ensure that the current thread is attached to the VM and call fn"
        Java.perform(function() {

            {{ content }}

        });

    } catch (err) {

        var response = {
            status: 'error',
            error_reason: err.message,
            type: 'global-exception',
            data: {}
        }

        send(JSON.stringify(response));
    }

} else {

    var response = {
        status: 'error',
        error_reason: 'Java runtime is not available.',
        type: 'global-exception',
        data: {}
    }

    send(JSON.stringify(response));
}
