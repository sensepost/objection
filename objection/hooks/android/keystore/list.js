// Dump entries in the Android Keystore, together with a flag
// indicating if its a key or a certificate.
//
// Ref: https://developer.android.com/reference/java/security/KeyStore.html

var KeyStore = Java.use('java.security.KeyStore');
var entries = [];

// Prepare the AndroidKeyStore keystore provider and load it. 
// Maybe at a later stage we should support adding other stores
// like from file or JKS.
var ks = KeyStore.getInstance('AndroidKeyStore');
ks.load(null, null);

// Get the aliases and loop through them. The aliases() method
// return an Enumeration<String> type.
var aliases = ks.aliases();

while (aliases.hasMoreElements()) {

    var alias = aliases.nextElement();

    entries.push({
        'alias': alias.toString(),
        'is_key': ks.isKeyEntry(alias),
        'is_certificate': ks.isCertificateEntry(alias)
    })
}

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'android-keystore-list',
    data: entries
};

send(response);

// - Sample Java
//
// KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
// ks.load(null);
// Enumeration<String> aliases = ks.aliases();
//
// while(aliases.hasMoreElements()) {
//     Log.e("E", "Aliases = " + aliases.nextElement());
// }
