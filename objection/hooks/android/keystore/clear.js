// Delete all entries in the Android Keystore
//
// Ref: https://developer.android.com/reference/java/security/KeyStore.html#deleteEntry(java.lang.String)

var KeyStore = Java.use('java.security.KeyStore');

// Prepare the AndroidKeyStore keystore provider and load it. 
// Maybe at a later stage we should support adding other stores
// like from file or JKS.
var ks = KeyStore.getInstance('AndroidKeyStore');
ks.load(null, null);

// Get the aliases and loop through them. The aliases() method
// return an Enumeration<String> type.
var aliases = ks.aliases();

while (aliases.hasMoreElements()) {

    ks.deleteEntry(aliases.nextElement()); 
}

var response = {
    status: 'success',
    error_reason: NaN,
    type: 'android-keystore-clear',
    data: NaN
};

send(response);

// - Sample Java
//
// KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
// ks.load(null);
// Enumeration<String> aliases = ks.aliases();
//
// while(aliases.hasMoreElements()) {
//     ks.deleteEntry(aliases.nextElement());
// }
