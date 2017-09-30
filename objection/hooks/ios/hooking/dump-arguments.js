// Hooks an Objective-C class method and attempts to dump its
// arguments as it is called.

var resolver = new ApiResolver('objc');
var method = {};
var argument_count = '{{ argument_count }}';

resolver.enumerateMatches('{{ method }}', {
    onMatch: function (match) {
        method.name = match.name;
        method.address = match.address;
    },
    onComplete: function () { }
});

if (method.address) {

    send({
        status: 'success',
        error_reason: NaN,
        type: 'ios-argument-dump',
        data: 'Found address for: {{ method }} at ' + method.address
    });

    // check the argument count that we need to loop over
    var ac = parseInt(argument_count);

    Interceptor.attach(method.address, {
        onEnter: function (args) {

            send({
                status: 'success',
                error_reason: NaN,
                type: 'ios-argument-dump',
                data: 'Detected call to: {{ method }}'
            });

            if (ac > 0) {

                var parsed_args = '{{ method }}';
                var split_method = parsed_args.split(':');

                // As this is an ObjectiveC method, the arguments are as follows:
                // 0. 'self'
                // 1. The selector (object.name:)
                // 2. The first arg
                //
                // For this reason do we adjust it by 2 positions
                for (var i=0; i < ac; i++) {

                    var obj = ObjC.Object(args[i+2]);
                    var selector = split_method[i];

                    selector = selector + ':"' + obj.toString() + '"';
                    split_method[i] = selector;
                }

                send({
                    status: 'success',
                    error_reason: NaN,
                    type: 'ios-argument-dump',
                    data: split_method.join(' ')
                });
            }
        }
    });

} else {

    send({
        status: 'error',
        error_reason: 'Unable to find address for {{ method }}. Is the selector valid?',
        type: 'ios-argument-dump',
        data: NaN
    });
}
