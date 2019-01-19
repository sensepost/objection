import { colors as c } from "../lib/color";
import { IKeyStoreEntry } from "./lib/interfaces";
import { wrapJavaPerform } from "./lib/libjava";
import { JavaClass } from "./lib/types";

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
      const KeyStore: JavaClass = Java.use("java.security.KeyStore");
      const entries: IKeyStoreEntry[] = [];

      // Prepare the AndroidKeyStore keystore provider and load it.
      // Maybe at a later stage we should support adding other stores
      // like from file or JKS.
      const ks: JavaClass = KeyStore.getInstance("AndroidKeyStore");
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
      const KeyStore: JavaClass = Java.use("java.security.KeyStore");

      // Prepare the AndroidKeyStore keystore provider and load it.
      // Maybe at a later stage we should support adding other stores
      // like from file or JKS.
      const ks: JavaClass = KeyStore.getInstance("AndroidKeyStore");
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
}
