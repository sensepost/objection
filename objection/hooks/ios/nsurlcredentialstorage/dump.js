// Dumps contents of NSURLCredentialStorage for all protection spaces

var NSURLCredentialStorage = ObjC.classes.NSURLCredentialStorage;

rpc.exports = {
    dump: function () {

        var data = [];
        var credentialsDict = NSURLCredentialStorage.sharedCredentialStorage().allCredentials();

        if (credentialsDict.count() <= 0) {
            return data;
        }

        var protectionSpaceEnumerator = credentialsDict.keyEnumerator();
        var urlProtectionSpace;

        while ((urlProtectionSpace = protectionSpaceEnumerator.nextObject()) !== null) {

            var userNameEnumerator = credentialsDict.objectForKey_(urlProtectionSpace).keyEnumerator();
            var userName;
            while ((userName = userNameEnumerator.nextObject()) !== null) {

                var creds = credentialsDict.objectForKey_(urlProtectionSpace).objectForKey_(userName);

                // Add the creds for this protection space.
                data.push({
                    'Host': urlProtectionSpace.host().toString(),
                    'Authentication Method': urlProtectionSpace.authenticationMethod().toString(),
                    'Protocol': urlProtectionSpace.protocol().toString(),
                    'Port': urlProtectionSpace.port(),
                    'User': creds.user().toString(),
                    'Password': creds.password().toString(),
                });
            }
        }

        return data;
    }
}

// -- Sample ObjC
// Source: https://stackoverflow.com/q/49827490
//
// NSDictionary *credentialsDict = [[NSURLCredentialStorage sharedCredentialStorage] allCredentials];
// NSLog(@"Got all credentials as: %@", credentialsDict);

// if ([credentialsDict count] > 0) {
//     // the credentialsDict has NSURLProtectionSpace objs as keys and dicts of userName => NSURLCredential
//     NSEnumerator *protectionSpaceEnumerator = [credentialsDict keyEnumerator];
//     id urlProtectionSpace;

//     // iterate over all NSURLProtectionSpaces
//     while (urlProtectionSpace = [protectionSpaceEnumerator nextObject]) {
//         NSEnumerator *userNameEnumerator = [[credentialsDict objectForKey:urlProtectionSpace] keyEnumerator];
//         id userName;

//         // iterate over all usernames for this protectionspace, which are the keys for the actual NSURLCredentials
//         while (userName = [userNameEnumerator nextObject]) {
//             NSURLCredential *cred = [[credentialsDict objectForKey:urlProtectionSpace] objectForKey:userName];
//             NSLog(@"cred: %@", cred);
//             NSLog(@"%@", [cred password]);
//             NSLog(@"%@", [cred identity]);
//             NSLog(@"%lu", (unsigned long)[cred persistence]);
//         }
//     }
// }
