if (ObjC.available) {

    try {

        {{ content }}

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
        error_reason: 'Objective-C runtime is not available.',
        type: 'global-exception',
        data: {}
    };

    send(response);
}
