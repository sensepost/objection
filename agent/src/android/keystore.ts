import { colors as c } from "../lib/color";
import { IKeyStoreEntry } from "./lib/interfaces";
import { wrapJavaPerform } from "./lib/libjava";
import { KeyStore } from "./lib/types";
import { IJob } from "../lib/interfaces";
import { jobs } from "../lib/jobs";

export namespace keystore {

  // Dump entries in the Android Keystore, together with a flag
  // indicating if its a key or a certificate.
  //
  // Ref: https://developer.android.com/reference/java/security/KeyStore.html
  export const list = (): Promise<IKeyStoreEntry[]> => {
    // - Sample Java
    //
    // KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
    // ks.load(null);
    // Enumeration<String> aliases = ks.aliases();
    //
    // while(aliases.hasMoreElements()) {
    //     Log.e("E", "Aliases = " + aliases.nextElement());
    // }
    return wrapJavaPerform(() => {
      const keyStore: KeyStore = Java.use("java.security.KeyStore");
      const entries: IKeyStoreEntry[] = [];

      // Prepare the AndroidKeyStore keystore provider and load it.
      // Maybe at a later stage we should support adding other stores
      // like from file or JKS.
      const ks: KeyStore = keyStore.getInstance("AndroidKeyStore");
      ks.load(null, null);

      // Get the aliases and loop through them. The aliases() method
      // return an Enumeration<String> type.
      const aliases = ks.aliases();
      while (aliases.hasMoreElements()) {
        const alias = aliases.nextElement();

        entries.push({
          alias: alias.toString(),
          is_certificate: ks.isCertificateEntry(alias),
          is_key: ks.isKeyEntry(alias),
        });
      }

      return entries;
    });
  };

  //https://labs.f-secure.com/blog/how-secure-is-your-android-keystore-authentication
  //https://github.com/FSecureLABS/android-keystore-audit
  function KeystoreInfo(keyAlias) {
    let result: any = {};

    Java.perform(function () {
      var keyStoreCls = Java.use('java.security.KeyStore');
      var keyFactoryCls = Java.use('java.security.KeyFactory');
      var keyInfoCls = Java.use('android.security.keystore.KeyInfo');
      var keySecretKeyFactoryCls = Java.use('javax.crypto.SecretKeyFactory');
      var keyFactoryObj = null;

      var keyStoreObj = keyStoreCls.getInstance('AndroidKeyStore');
      keyStoreObj.load(null);
      var key = keyStoreObj.getKey(keyAlias, null);
      if (key == null) {
        console.log('key does not exist');
        return null;
      }
      try {
        keyFactoryObj = keyFactoryCls.getInstance(key.getAlgorithm(), 'AndroidKeyStore');
      } catch (err) {
        keyFactoryObj = keySecretKeyFactoryCls.getInstance(key.getAlgorithm(), 'AndroidKeyStore');
      }
      var keyInfo = keyFactoryObj.getKeySpec(key, keyInfoCls.class);
      result.keyAlgorithm = key.getAlgorithm();
      result.keySize = keyInfoCls['getKeySize'].call(keyInfo);
      result.blockModes = keyInfoCls['getBlockModes'].call(keyInfo);
      result.digests = keyInfoCls['getDigests'].call(keyInfo);
      result.encryptionPaddings = keyInfoCls['getEncryptionPaddings'].call(keyInfo);
      result.keyValidityForConsumptionEnd = keyInfoCls['getKeyValidityForConsumptionEnd'].call(keyInfo);
      if (result.keyValidityForConsumptionEnd != null) result.keyValidityForConsumptionEnd = result.keyValidityForConsumptionEnd.toString();
      result.keyValidityForOriginationEnd = keyInfoCls['getKeyValidityForOriginationEnd'].call(keyInfo);
      if (result.keyValidityForOriginationEnd != null) result.keyValidityForOriginationEnd = result.keyValidityForOriginationEnd.toString();
      result.keyValidityStart = keyInfoCls['getKeyValidityStart'].call(keyInfo);
      if (result.keyValidityStart != null) result.keyValidityStart = result.keyValidityStart.toString();
      result.keystoreAlias = keyInfoCls['getKeystoreAlias'].call(keyInfo);
      result.origin = keyInfoCls['getOrigin'].call(keyInfo);
      result.purposes = keyInfoCls['getPurposes'].call(keyInfo);
      result.signaturePaddings = keyInfoCls['getSignaturePaddings'].call(keyInfo);
      result.userAuthenticationValidityDurationSeconds = keyInfoCls['getUserAuthenticationValidityDurationSeconds'].call(keyInfo);
      result.isInsideSecureHardware = keyInfoCls['isInsideSecureHardware'].call(keyInfo);
      result.isInvalidatedByBiometricEnrollment = keyInfoCls['isInvalidatedByBiometricEnrollment'].call(keyInfo);
      try { result.isTrustedUserPresenceRequired = keyInfoCls['isTrustedUserPresenceRequired'].call(keyInfo); } catch (err) { }
      result.isUserAuthenticationRequired = keyInfoCls['isUserAuthenticationRequired'].call(keyInfo);
      result.isUserAuthenticationRequirementEnforcedBySecureHardware = keyInfoCls['isUserAuthenticationRequirementEnforcedBySecureHardware'].call(keyInfo);
      result.isUserAuthenticationValidWhileOnBody = keyInfoCls['isUserAuthenticationValidWhileOnBody'].call(keyInfo);
      try { result.isUserConfirmationRequired = keyInfoCls['isUserConfirmationRequired'].call(keyInfo); } catch (err) { }
     });
    return result;
  }
  export const listDetails = () => {
    return wrapJavaPerform(() => {
      const keyStore: KeyStore = Java.use("java.security.KeyStore");
      const ks: KeyStore = keyStore.getInstance("AndroidKeyStore");
      ks.load(null, null);
      const aliases = ks.aliases();
      
      while (aliases.hasMoreElements()) {
          var alias = aliases.nextElement()
          var keystoreInfo = KeystoreInfo(alias.toString())
          
          c.log(alias)
          c.log(JSON.stringify(keystoreInfo, null, 4))
          c.log("\n")
      }      
    });
  };

  // Delete all entries in the Android Keystore
  //
  // Ref: https://developer.android.com/reference/java/security/KeyStore.html#deleteEntry(java.lang.String)
  export const clear = () => {
    // - Sample Java
    //
    // KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
    // ks.load(null);
    // Enumeration<String> aliases = ks.aliases();
    //
    // while(aliases.hasMoreElements()) {
    //     ks.deleteEntry(aliases.nextElement());
    // }
    return wrapJavaPerform(() => {
      const keyStore: KeyStore = Java.use("java.security.KeyStore");

      // Prepare the AndroidKeyStore keystore provider and load it.
      // Maybe at a later stage we should support adding other stores
      // like from file or JKS.
      const ks: KeyStore = keyStore.getInstance("AndroidKeyStore");
      ks.load(null, null);

      // Get the aliases and loop through them. The aliases() method
      // return an Enumeration<String> type.
      const aliases = ks.aliases();
      while (aliases.hasMoreElements()) {
        ks.deleteEntry(aliases.nextElement());
      }

      send(c.blackBright(`Keystore entries cleared`));
    });
  };

  // keystore watch methods

  // Watch for KeyStore.load();
  // TODO: Store the keystores themselves maybe?
  const keystoreLoad = (ident: string): any | undefined => {
    return wrapJavaPerform(() => {
      const ks: KeyStore = Java.use("java.security.KeyStore");
      const ksLoad = ks.load.overload("java.io.InputStream", "[C");
      send(c.blackBright(`[${ident}] Watching Keystore.load("java.io.InputStream", "[C")`));

      ksLoad.implementation = function (stream, password) {
        send(c.blackBright(`[${ident}] `) +
          `Keystore.load(${c.greenBright(stream)}, ${c.redBright(password || `null`)}) ` +
          `called, loading a ${c.cyanBright(this.getType())} keystore.`);
        return this.load(stream, password);
      }
    });
  };

  // Watch for Keystore.getKey().
  // TODO: Extract more information, like the key itself maybe?
  const keystoreGetKey = (ident: string): any | undefined => {
    return wrapJavaPerform(() => {
      const ks: KeyStore = Java.use("java.security.KeyStore");
      const ksGetKey = ks.getKey.overload("java.lang.String", "[C");
      send(c.blackBright(`[${ident}] Watching Keystore.getKey("java.lang.String", "[C")`));

      ksGetKey.implementation = function (alias, password) {
        const key = this.getKey(alias, password);
        send(c.blackBright(`[${ident}] `) +
          `Keystore.getKey(${c.greenBright(alias)}, ${c.redBright(password || `null`)}) ` +
          `called, returning a ${c.greenBright(key.$className)} instance.`);
        return key;
      }
      return ksGetKey;
    });
  }

  // Android KeyStore watcher.
  // Many, many more methods can be added here..
  export const watchKeystore = (): void => {
    const job: IJob = {
      identifier: jobs.identifier(),
      implementations: [],
      type: "android-keystore-watch",
    };

    job.implementations.push(keystoreLoad(job.identifier));
    job.implementations.push(keystoreGetKey(job.identifier));
    jobs.add(job);
  }
}
