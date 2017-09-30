// Lists the modules available in the current process.

var modules = [];

var process_modules = Process.enumerateModules({
    onMatch: function(module) {
        modules.push(module);
    },
    onComplete: function() {}
});

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'frida-environment',
    data: {
        modules
    }
};

send(response);
