// Watches for invocations of a specific Objective-C method.

var resolver = new ApiResolver('objc');
var method = {};

resolver.enumerateMatches('{{ selector }}', {
    onMatch: function (match) {
        method.name = match.name;
        method.address = match.address;
    },
    onComplete: function () { }
});

if (method.address) {

    send(JSON.stringify({
        status: 'success',
        error_reason: NaN,
        type: 'watch-class-method',
        data: 'Found address for: {{ selector }} at ' + method.address
    }));

    Interceptor.attach(method.address, {
        onEnter: function (args) {

            var receiver = new ObjC.Object(args[0]);
            var message = '(Kind: ' + receiver.$kind +
                ') (Super: ' + receiver.$superClass +
                ') [' + receiver.$className + ' ' + ObjC.selectorAsString(args[1]) + ']';


            // if we should include a backtrace to here, do that.
            if ('{{ include_backtrace }}' == 'True') {

                message = message + '\nBacktrace:\n\t' +
                    Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join('\n\t')

            }

            send(JSON.stringify({
                status: 'success',
                error_reason: NaN,
                type: 'watch-class-method',
                data: 'Hit: ' + message
            }));
        }
    });

} else {

    send(JSON.stringify({
        status: 'error',
        error_reason: 'Unable to find address for {{ selector }}. Is the selector valid?',
        type: 'watch-class-method',
        data: NaN
    }));
}
