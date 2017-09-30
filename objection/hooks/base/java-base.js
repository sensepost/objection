if (Java.available) {

    try {

        // From Frida documentation:
        //  "ensure that the current thread is attached to the VM and call fn"
        //
        // We also handle the exception that could happen within the callback as
        // it does not seem to bubble outside of it.
        Java.perform(function () {

            try {

                {{ content }}

            } catch (err) {

                var response = {
                    status: 'error',
                    error_reason: err.message,
                    type: 'java-perform-exception',
                    data: {}
                };

                send(response);
            }
        });

    } catch (err) {

        var response = {
            status: 'error',
            error_reason: err.message,
            type: 'global-exception',
            data: {}
        };

        send(response);
    }

} else {

    var response = {
        status: 'error',
        error_reason: 'Java runtime is not available.',
        type: 'global-exception',
        data: {}
    };

    send(response);
}
