// Attempts to bypass SSL pinning implementations in a number of
// ways. These include implementing a new TrustManager that will
// accept any SSL certificate, overriding OkHTTP v3 check()
// method etc.

var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
var SSLContext = Java.use('javax.net.ssl.SSLContext');
var quiet_output = ('{{ quiet }}'.toLowerCase() == 'true')

// Helper method to honor the quiet flag.
function quiet_send(data) {

    if (quiet_output) {

        return;
    }

    send(data)
}

// Implement a new TrustManager
// ref: https://gist.github.com/oleavr/3ca67a173ff7d207c6b8c3b0ca65a9d8
var TrustManager = Java.registerClass({
    name: 'com.sensepost.test.TrustManager',
    implements: [X509TrustManager],
    methods: {
        checkClientTrusted: function (chain, authType) {
        },
        checkServerTrusted: function (chain, authType) {
        },
        getAcceptedIssuers: function () {
            return [];
        }
    }
});

// Prepare the TrustManagers array to pass to SSLContext.init()
var TrustManagers = [TrustManager.$new()];

send({
    status: 'success',
    error_reason: NaN,
    type: 'android-ssl-pinning-bypass',
    data: 'Custom, Empty TrustManager ready'
});

// Get a handle on the init() on the SSLContext class
var SSLContext_init = SSLContext.init.overload(
    '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');

// Override the init method, specifying our new TrustManager
SSLContext_init.implementation = function (keyManager, trustManager, secureRandom) {

    quiet_send({
        status: 'success',
        error_reason: NaN,
        type: 'android-ssl-pinning-bypass',
        data: 'Overriding SSLContext.init() with the custom TrustManager'
    });

    SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
};

// OkHTTP v3.x

// Wrap the logic in a try/catch as not all applications will have
// okhttp as part of the app.
try {

    var CertificatePinner = Java.use('okhttp3.CertificatePinner');

    send({
        status: 'success',
        error_reason: NaN,
        type: 'android-ssl-pinning-bypass',
        data: 'OkHTTP 3.x Found'
    });

    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function () {

        quiet_send({
            status: 'success',
            error_reason: NaN,
            type: 'android-ssl-pinning-bypass',
            data: 'OkHTTP 3.x check() called. Not throwing an exception.'
        });
    }

} catch (err) {

    // If we dont have a ClassNotFoundException exception, raise the
    // problem encountered.
    if (err.message.indexOf('ClassNotFoundException') === 0) {

        throw new Error(err);
    }
}

// Appcelerator Titanium PinningTrustManager

// Wrap the logic in a try/catch as not all applications will have
// appcelerator as part of the app.
try {

    var PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');

    send({
        status: 'success',
        error_reason: NaN,
        type: 'android-ssl-pinning-bypass',
        data: 'Appcelerator Titanium Found'
    });

    PinningTrustManager.checkServerTrusted.implementation = function () {

        quiet_send({
            status: 'success',
            error_reason: NaN,
            type: 'android-ssl-pinning-bypass',
            data: 'Appcelerator checkServerTrusted() called. Not throwing an exception.'
        });
    }

} catch (err) {

    // If we dont have a ClassNotFoundException exception, raise the
    // problem encountered.
    if (err.message.indexOf('ClassNotFoundException') === 0) {

        throw new Error(err);
    }
}

// -- Sample Java
//
// "Generic" TrustManager Example
//
// TrustManager[] trustAllCerts = new TrustManager[] {
//     new X509TrustManager() {
//         public java.security.cert.X509Certificate[] getAcceptedIssuers() {
//             return null;
//         }
//         public void checkClientTrusted(X509Certificate[] certs, String authType) {  }

//         public void checkServerTrusted(X509Certificate[] certs, String authType) {  }

//     }
// };

// SSLContext sslcontect = SSLContext.getInstance("TLS");
// sslcontect.init(null, trustAllCerts, null);

// OkHTTP 3 Pinning Example
// String hostname = "swapi.co";
// CertificatePinner certificatePinner = new CertificatePinner.Builder()
//         .add(hostname, "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
//         .build();

// OkHttpClient client = new OkHttpClient.Builder()
//         .certificatePinner(certificatePinner)
//         .build();

// Request request = new Request.Builder()
//         .url("https://swapi.co/api/people/1")
//         .build();

// Response response = client.newCall(request).execute();
