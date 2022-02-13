import { colors as c } from "../lib/color";
import {
  IKeyStoreDetail,
  IKeyStoreEntry
} from "./lib/interfaces";
import { wrapJavaPerform } from "./lib/libjava";
import {
  KeyFactory,
  KeyInfo,
  KeyStore,
  SecretKeyFactory
} from "./lib/types";
import { IJob } from "../lib/interfaces";
import * as jobs from "../lib/jobs";

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

// Dump detailed information about keystore entries per alias.
//
// Refs:
//  https://labs.f-secure.com/blog/how-secure-is-your-android-keystore-authentication
//  https://github.com/FSecureLABS/android-keystore-audit
export const detail = (): Promise<IKeyStoreDetail[]> => {

  // helper function to extract  keystore alias information
  const keystore_info = (alias): IKeyStoreDetail => {
    const r: IKeyStoreDetail = {};

    wrapJavaPerform(() => {
      // java class handles
      const keyStore: KeyStore = Java.use('java.security.KeyStore');
      const keyFactory: KeyFactory = Java.use('java.security.KeyFactory');
      const keyInfo: KeyInfo = Java.use('android.security.keystore.KeyInfo');
      const keySecretKeyFactory: SecretKeyFactory = Java.use('javax.crypto.SecretKeyFactory');

      // load the keystore entry
      const keyStoreObj = keyStore.getInstance('AndroidKeyStore');
      keyStoreObj.load(null);
      const key = keyStoreObj.getKey(alias, null);
      if (key == null) return null;

      let keySpec = null;
      try {
        keySpec = keyFactory.getInstance(key.getAlgorithm(), 'AndroidKeyStore')
          .getKeySpec(key, keyInfo.class);
      } catch (err) {
        keySpec = keySecretKeyFactory.getInstance(key.getAlgorithm(), 'AndroidKeyStore')
          .getKeySpec(key, keyInfo.class);
      }

      // set result fields
      r.keyAlgorithm = key.getAlgorithm();
      r.keySize = keyInfo['getKeySize'].call(keySpec);
      r.blockModes = keyInfo['getBlockModes'].call(keySpec);
      r.digests = keyInfo['getDigests'].call(keySpec);
      r.encryptionPaddings = keyInfo['getEncryptionPaddings'].call(keySpec);
      r.keyValidityForConsumptionEnd = keyInfo['getKeyValidityForConsumptionEnd'].call(keySpec);
      r.keyValidityForOriginationEnd = keyInfo['getKeyValidityForOriginationEnd'].call(keySpec);
      r.keyValidityStart = keyInfo['getKeyValidityStart'].call(keySpec);
      r.keystoreAlias = keyInfo['getKeystoreAlias'].call(keySpec);
      r.origin = keyInfo['getOrigin'].call(keySpec);
      r.purposes = keyInfo['getPurposes'].call(keySpec);
      r.signaturePaddings = keyInfo['getSignaturePaddings'].call(keySpec);
      r.userAuthenticationValidityDurationSeconds = keyInfo['getUserAuthenticationValidityDurationSeconds'].call(keySpec);
      r.isInsideSecureHardware = keyInfo['isInsideSecureHardware'].call(keySpec);
      r.isInvalidatedByBiometricEnrollment = keyInfo['isInvalidatedByBiometricEnrollment'].call(keySpec);
      r.isUserAuthenticationRequired = keyInfo['isUserAuthenticationRequired'].call(keySpec);
      r.isUserAuthenticationRequirementEnforcedBySecureHardware = keyInfo['isUserAuthenticationRequirementEnforcedBySecureHardware'].call(keySpec);
      r.isUserAuthenticationValidWhileOnBody = keyInfo['isUserAuthenticationValidWhileOnBody'].call(keySpec);

      // "crashy" calls that's ok if they fail
      try {
        r.isTrustedUserPresenceRequired = keyInfo['isTrustedUserPresenceRequired'].call(keySpec);
      } catch (err) { }
      try {
        r.isUserConfirmationRequired = keyInfo['isUserConfirmationRequired'].call(keySpec);
      } catch (err) { }

      // translate some values to string representation if they are not empty
      if (r.keyValidityForConsumptionEnd != null)
        r.keyValidityForConsumptionEnd = r.keyValidityForConsumptionEnd.toString();
      if (r.keyValidityForOriginationEnd != null)
        r.keyValidityForOriginationEnd = r.keyValidityForOriginationEnd.toString();
      if (r.keyValidityStart != null)
        r.keyValidityStart = r.keyValidityStart.toString();
    });

    return r;
  };

  return wrapJavaPerform((): IKeyStoreDetail[] => {
    const keyStore: KeyStore = Java.use("java.security.KeyStore");
    const ks: KeyStore = keyStore.getInstance("AndroidKeyStore");
    ks.load(null, null);

    const aliases = ks.aliases();
    const info: IKeyStoreDetail[] = [];

    while (aliases.hasMoreElements()) {
      var a = aliases.nextElement();
      info.push(keystore_info(a.toString()));
    }

    return info;
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
    };
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
    };
    return ksGetKey;
  });
};

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
};
