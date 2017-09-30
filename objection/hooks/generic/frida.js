// Returns information about Frida itself.

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'frida-environment',
    data: {
        frida_version: Frida.version,
        process_arch: Process.arch,
        process_platform: Process.platform,
        process_has_debugger: Process.isDebuggerAttached()
    }
};

send(response);
