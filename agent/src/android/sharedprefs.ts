import { colors as c } from "../lib/color";
import { IJob } from "../lib/interfaces";
import * as jobs from "../lib/jobs";
import {
  wrapJavaPerform
} from "./lib/libjava";

function setToArray(set) {
  return set == null ? null : set.toArray()
}

export const monitor = (encrypted_only: boolean): Promise<void> => {
  send(`Monitoring shared preferences`);

  const job: IJob = {
    identifier: jobs.identifier(),
    implementations: [],
    type: `shared-prefs-monitor`,
  };
  jobs.add(job)
  return wrapJavaPerform(() => {
    if (encrypted_only == false) {
      // SharedPreferences
      const hSharedPrefs = Java.use('android.app.SharedPreferencesImpl')

      hSharedPrefs["getBoolean"].overload('java.lang.String', 'boolean').implementation = function (key, _default) {
        const returnValue = this["getBoolean"].apply(this, arguments)
        send(`SharedPreferences::getBoolean(${c.green(key)}, ${c.yellow(_default)}) -> ${c.yellow(returnValue)}`)
      

        return returnValue
      }
      job.implementations.push(hSharedPrefs["getBoolean"])

      hSharedPrefs["getFloat"].overload('java.lang.String', 'float').implementation = function (key, _default) {
        const returnValue = this["getFloat"].apply(this, arguments)
        send(`SharedPreferences::getFloat(${c.green(key)}, ${c.yellow(_default)}) -> ${c.yellow(returnValue)}`)
        return returnValue
      }
      job.implementations.push(hSharedPrefs["getFloat"])

      hSharedPrefs["getInt"].overload('java.lang.String', 'int').implementation = function (key, _default) {
        const returnValue = this["getInt"].apply(this, arguments)
        send(`SharedPreferences::getInt(${c.green(key)}, ${c.yellow(_default)}) -> ${c.yellow(returnValue)}`)
        return returnValue
      }
      job.implementations.push(hSharedPrefs["getInt"].overload('java.lang.String', 'int').implementation)

      hSharedPrefs["getLong"].overload('java.lang.String', 'long').implementation = function (key, _default) {
        const returnValue = this["getLong"].apply(this, arguments)
        send(`SharedPreferences::getLong(${c.green(key)}, ${c.yellow(_default)}) -> ${c.yellow(returnValue)}`)
        return returnValue
      }
      job.implementations.push(hSharedPrefs["getLong"])

      hSharedPrefs["getString"].overload('java.lang.String', 'java.lang.String').implementation = function (key, _default) {
        const returnValue = this["getString"].apply(this, arguments)
        send(`SharedPreferences::getString(${c.green(key)}, ${c.yellow(_default)}) -> ${c.yellow(returnValue)}`)
        return returnValue
      }
      job.implementations.push(hSharedPrefs["getString"])

      hSharedPrefs["getStringSet"].overload('java.lang.String', 'java.util.Set').implementation = function (key, _default) {
        const returnValue = this["getStringSet"].apply(this, arguments)
        send(`SharedPreferences::getStringSet(${c.green(key)}, ${c.yellow(setToArray(_default))}) -> ${c.yellow(setToArray(returnValue))}`)
        return returnValue
      }
      job.implementations.push(hSharedPrefs["getStringSet"])

      // SharedPreferences$Editor
      const hSharedPrefsEditor = Java.use('android.app.SharedPreferencesImpl$EditorImpl')

      hSharedPrefsEditor["putBoolean"].overload('java.lang.String', 'boolean').implementation = function (key, val) {
        send(`SharedPreferences$Editor::putBoolean(${c.green(key)}, ${c.yellow(val)})`)
        const returnValue = this["putBoolean"].apply(this, arguments)
        return returnValue
      }
      job.implementations.push(hSharedPrefsEditor["putBoolean"])

      hSharedPrefsEditor["putFloat"].overload('java.lang.String', 'float').implementation = function (key, val) {
        send(`SharedPreferences$Editor::putFloat(${c.green(key)}, ${c.yellow(val)})`)
        const returnValue = this["putFloat"].apply(this, arguments)
        return returnValue
      }
      job.implementations.push(hSharedPrefsEditor["putFloat"])

      hSharedPrefsEditor["putInt"].overload('java.lang.String', 'int').implementation = function (key, val) {
        send(`SharedPreferences$Editor::putInt(${c.green(key)}, ${c.yellow(val)})`)
        const returnValue = this["putInt"].apply(this, arguments)
        return returnValue
      }
      job.implementations.push(hSharedPrefsEditor["putInt"])

      hSharedPrefsEditor["putLong"].overload('java.lang.String', 'long').implementation = function (key, val) {
        send(`SharedPreferences$Editor::putLong(${c.green(key)}, ${c.yellow(val)})`)
        const returnValue = this["putLong"].apply(this, arguments)
        return returnValue
      }
      job.implementations.push(hSharedPrefsEditor["putLong"])

      hSharedPrefsEditor["putString"].overload('java.lang.String', 'java.lang.String').implementation = function (key, val) {
        send(`SharedPreferences$Editor::putString(${c.green(key)}, ${c.yellow(val)})`)
        const returnValue = this["putString"].apply(this, arguments)
        return returnValue
      }
      job.implementations.push(hSharedPrefsEditor["putString"])

      hSharedPrefsEditor["putStringSet"].overload('java.lang.String', 'java.util.Set').implementation = function (key, val) {
        send(`SharedPreferences$Editor::putStringSet(${c.green(key)}, ${c.yellow(val.toArray())})`)
        const returnValue = this["putStringSet"].apply(this, arguments)
        return returnValue
      }
      job.implementations.push(hSharedPrefsEditor["putStringSet"])
    }

    try {
      // EncryptedSharedPreferences
      const hEncryptedSharedPrefs = Java.use('androidx.security.crypto.EncryptedSharedPreferences')

      hEncryptedSharedPrefs["getBoolean"].overload('java.lang.String', 'boolean').implementation = function (key, _default) {
        const returnValue = this["getBoolean"].apply(this, arguments)
        send(`EncryptedSharedPreferences::getBoolean(${c.green(key)}, ${c.yellow(_default)}) -> ${c.yellow(returnValue)}`)
        return returnValue
      }
      job.implementations.push(hEncryptedSharedPrefs["getBoolean"])

      hEncryptedSharedPrefs["getFloat"].overload('java.lang.String', 'float').implementation = function (key, _default) {
        const returnValue = this["getFloat"].apply(this, arguments)
        send(`EncryptedSharedPreferences::getFloat(${c.green(key)}, ${c.yellow(_default)}) -> ${c.yellow(returnValue)}`)
        return returnValue
      }
      job.implementations.push(hEncryptedSharedPrefs["getFloat"])

      hEncryptedSharedPrefs["getInt"].overload('java.lang.String', 'int').implementation = function (key, _default) {
        const returnValue = this["getInt"].apply(this, arguments)
        send(`EncryptedSharedPreferences::getInt(${c.green(key)}, ${c.yellow(_default)}) -> ${c.yellow(returnValue)}`)
        return returnValue
      }
      job.implementations.push(hEncryptedSharedPrefs["getInt"])

      hEncryptedSharedPrefs["getLong"].overload('java.lang.String', 'long').implementation = function (key, _default) {
        const returnValue = this["getLong"].apply(this, arguments)
        send(`EncryptedSharedPreferences::getLong(${c.green(key)}, ${c.yellow(_default)}) -> ${c.yellow(returnValue)}`)
        return returnValue
      }
      job.implementations.push(hEncryptedSharedPrefs["getLong"])

      hEncryptedSharedPrefs["getString"].overload('java.lang.String', 'java.lang.String').implementation = function (key, _default) {
        const returnValue = this["getString"].apply(this, arguments)
        send(`EncryptedSharedPreferences::getString(${c.green(key)}, ${c.yellow(_default)}) -> ${c.yellow(returnValue)}`)
        return returnValue
      }
      job.implementations.push(hEncryptedSharedPrefs["getString"])

      hEncryptedSharedPrefs["getStringSet"].overload('java.lang.String', 'java.util.Set').implementation = function (key, _default) {
        const returnValue = this["getStringSet"].apply(this, arguments)
        send(`EncryptedSharedPreferences::getStringSet(${c.green(key)}, ${c.yellow(setToArray(_default))}) -> ${c.yellow(setToArray(returnValue))}`)
        return returnValue
      }
      job.implementations.push(hEncryptedSharedPrefs["getStringSet"])

      // EncryptedSharedPreferences$Editor
      const hEncryptedSharedPrefsEditor = Java.use('androidx.security.crypto.EncryptedSharedPreferences$Editor')

      hEncryptedSharedPrefsEditor["putBoolean"].overload('java.lang.String', 'boolean').implementation = function (key, val) {
        send(`EncryptedSharedPreferences$Editor::putBoolean(${c.green(key)}, ${c.yellow(val)})`)
        const returnValue = this["putBoolean"].apply(this, arguments)
        return returnValue
      }
      job.implementations.push(hEncryptedSharedPrefsEditor["putBoolean"])

      hEncryptedSharedPrefsEditor["putFloat"].overload('java.lang.String', 'float').implementation = function (key, val) {
        send(`EncryptedSharedPreferences$Editor::putFloat(${c.green(key)}, ${c.yellow(val)})`)
        const returnValue = this["putFloat"].apply(this, arguments)
        return returnValue
      }
      job.implementations.push(hEncryptedSharedPrefsEditor["putFloat"])

      hEncryptedSharedPrefsEditor["putInt"].overload('java.lang.String', 'int').implementation = function (key, val) {
        send(`EncryptedSharedPreferences$Editor::putInt(${c.green(key)}, ${c.yellow(val)})`)
        const returnValue = this["putInt"].apply(this, arguments)
        return returnValue
      }
      job.implementations.push(hEncryptedSharedPrefsEditor["putInt"])

      hEncryptedSharedPrefsEditor["putLong"].overload('java.lang.String', 'long').implementation = function (key, val) {
        send(`EncryptedSharedPreferences$Editor::putLong(${c.green(key)}, ${c.yellow(val)})`)
        const returnValue = this["putLong"].apply(this, arguments)
        return returnValue
      }
      job.implementations.push(hEncryptedSharedPrefsEditor["putLong"])

      hEncryptedSharedPrefsEditor["putString"].overload('java.lang.String', 'java.lang.String').implementation = function (key, val) {
        send(`EncryptedSharedPreferences$Editor::putString(${c.green(key)}, ${c.yellow(val)})`)
        const returnValue = this["putString"].apply(this, arguments)
        return returnValue
      }
      job.implementations.push(hEncryptedSharedPrefsEditor["putString"])

      hEncryptedSharedPrefsEditor["putStringSet"].overload('java.lang.String', 'java.util.Set').implementation = function (key, val) {
        send(`EncryptedSharedPreferences$Editor::putStringSet(${c.green(key)}, ${c.yellow(val.toArray())})`)
        const returnValue = this["putStringSet"].apply(this, arguments)
        return returnValue
      }
      job.implementations.push(hEncryptedSharedPrefsEditor["putStringSet"])
    } catch (error) {
      // Ignore this if it occurs, probably encrypted shared preferences is not used
    }
  });
};

/*
  This code has a lot of repetition that isn't required
  for a future PR maybe we could iterate over all loaded
  classes that extend SharedPrefs and Editor

  Since the interfaces developers use are going to be
  abstractions anyway, the same hooks could be applied
  to all instances.
*/