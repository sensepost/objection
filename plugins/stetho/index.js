rpc.exports = {
  initStetho: function () {
    Java.perform(function () {

      const stethoClassName = 'com.facebook.stetho.Stetho';
      const stethoJar = 'stetho.apk';

      const pathClassLoader = Java.use('dalvik.system.PathClassLoader');
      const javaFile = Java.use('java.io.File');
      const activityThread = Java.use('android.app.ActivityThread');

      const currentApplication = activityThread.currentApplication();
      const context = currentApplication.getApplicationContext();

      // Check if stetho is here already.
      console.log('Searching for stetho...');
      const stethoCheck = Java.enumerateLoadedClassesSync().filter(function (e) {
        return e.includes('com.facebook.stetho.Stetho');
      });

      if (stethoCheck.length > 0) {
        console.log('Stetho class already loaded!');
      } else {
        console.log('Stetho class not found, running classloader');

        const packageFilesDir = context.getCacheDir().getAbsolutePath().toString();
        const stethoJarDir = packageFilesDir + '/' + stethoJar;

        const javaStethoJarDir = javaFile.$new(stethoJarDir);
        if (!javaStethoJarDir.exists()) {
          console.log('Stetho jar is not available in cachedir at: ' + packageFilesDir);
          console.log('Stetho NOT successfully loaded');
          return;
        }

        // https://developer.android.com/reference/dalvik/system/PathClassLoader#PathClassLoader(java.lang.String,%20java.lang.String,%20java.lang.ClassLoader)
        const loader = pathClassLoader.$new(javaStethoJarDir.getAbsolutePath(), null, currentApplication.getClassLoader());

        console.log('Loading class ' + stethoClassName + ' using new classloader');
        loader.loadClass(stethoClassName);
      }

      // Attempt to use the new class. First, search for a specific classloader to use.
      try {

        console.log('Searching for the new stetho classloader...');
        const classLoaders = Java.enumerateClassLoadersSync().filter(function (l) {
          return l.toString().includes('stetho');
        });

        if (classLoaders.length != 1) { throw "No valid Stetho classloader found"; }

        Java.classFactory.loader = classLoaders[0];

        console.log('Using the class: ' + stethoClassName);

        const stetho = Java.use(stethoClassName);
        console.log('Calling initializeWithDefaults');
        stetho.initializeWithDefaults(context);

      } catch (err) {

        console.log('Failed to load by specifying the classloader with: ' + err.toString());
        console.log('Trying plan B...');

        try {

          const stetho = Java.use(stethoClassName);
          console.log('Calling initializeWithDefaults');
          stetho.initializeWithDefaults(context);

        } catch (err) {
          console.log('Could not find stetho without specifying a classloader either (plan B). Err: ' + err.toString());
          console.log('Stetho NOT successfully loaded');
          return;
        }
      }

      console.log('\nStetho up!');
    });
  }
}
