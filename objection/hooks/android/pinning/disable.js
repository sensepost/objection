// Attempts to bypass SSL pinning implementations by providing
// a new TrustManager that will accept any SSL certificate.

var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
var SSLContext = Java.use('javax.net.ssl.SSLContext');

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

send(JSON.stringify({
    status: 'success',
    error_reason: NaN,
    type: 'android-ssl-pinning-bypass',
    data: 'Custom TrustManager ready'
}));

// Get a handle on the init() on the SSLContext class
var SSLContext_init = SSLContext.init.overload(
    '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');

// Override the init method, specifying our new TrustManager
SSLContext_init.implementation = function (keyManager, trustManager, secureRandom) {

    send(JSON.stringify({
        status: 'success',
        error_reason: NaN,
        type: 'android-ssl-pinning-bypass',
        data: 'Overriding SSLContext.init() with the custom TrustManager'
    }));

    SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
}
