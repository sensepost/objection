// Depending on which runtime is available, return the
// appropriate device_type.

if (ObjC.available) {

    var response = {
        status: 'success',
        error_reason: NaN,
        type: 'device-type-enumeration',
        data: {
            device_type: 'ios',
            frida_version: Frida.version
        }
    };

    send(response);

} else if (Java.available) {

    var response = {
        status: 'success',
        error_reason: NaN,
        type: 'device-type-enumeration',
        data: {
            device_type: 'android',
            frida_version: Frida.version
        }
    };

    send(response);

} else {

    var response = {
        status: 'error',
        error_reason: 'Unknown Platform',
        type: 'device-type-enumeration',
        data: {
            device_type: 'unknown'
        }
    };

    send(response);
}
