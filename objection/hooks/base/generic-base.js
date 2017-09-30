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
