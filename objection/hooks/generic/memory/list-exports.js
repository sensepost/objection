// Lists exports from a specific import.

var exports = [];

var process_modules = Module.enumerateExports('{{ module }}', {
    onMatch: function(module) {
        exports.push(module);
    },
    onComplete: function() {}
});

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'module-exports',
    data: {
        exports
    }
};

send(response);
