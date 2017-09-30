// Enumerates cookies in from [NSHTTPCookieStorage sharedHTTPCookieStorage]

var NSHTTPCookieStorage = ObjC.classes.NSHTTPCookieStorage;
var cookieStore = NSHTTPCookieStorage.sharedHTTPCookieStorage();
var cookieJar = cookieStore.cookies();

var cookies = [];

if (cookieJar.count() > 0) {

    for (var i = 0; i < cookieJar.count(); i++) {

        // get the actual cookie from the jar
        var cookie = cookieJar.objectAtIndex_(i);

        // <NSHTTPCookie version:0 name:"__cfduid" value:"d2546c60b09a710a151d974e662f40c081498064665"
        // expiresDate:2018-06-21 17:04:25 +0000 created:2017-06-21 17:04:26 +0000 sessionOnly:FALSE
        // domain:".swapi.co" partition:"none" path:"/" isSecure:FALSE>
        var cookie_data = {
            version: cookie.version().toString(),
            name: cookie.name().toString(),
            value: cookie.value().toString(),
            expiresDate: cookie.expiresDate() ? cookie.expiresDate().toString() : 'null',
            // created: cookie.created().toString(),
            // sessionOnly: cookie.sessionOnly(),
            domain: cookie.domain().toString(),
            // partition: cookie.partition().toString(),
            path: cookie.path().toString(),
            isSecure: cookie.isSecure().toString(),
            isHTTPOnly: cookie.isHTTPOnly().toString()
        };

        cookies.push(cookie_data);
    }
}

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'cookies-get',
    data: cookies
};

send(response);

// -- Sample Objective-C
//
// NSHTTPCookieStorage *cs = [NSHTTPCookieStorage sharedHTTPCookieStorage];
// NSArray *cookies = [cs cookies];
