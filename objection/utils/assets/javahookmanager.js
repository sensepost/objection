// Frida Java hooking helper class.
//
// Edit the example below the HookManager class to suit your
// needs and then run with:
//  frida -U "App Name" --runtime=v8 -l objchookmanager.js
//
// Generated using objection:
//  https://github.com/sensepost/objection

class JavaHookManager {

  // create a new Hook for clazzName, specifying if we
  // want verbose logging of this class' internals.
  constructor(clazzName, verbose = false) {
    this.printVerbose(`Booting JavaHookManager for ${clazzName}...`);

    this.target = Java.use(clazzName);
    // store hooked methods as { method: x, replacements: [y1, y2] }
    this.hooking = [];
    this.available_methods = [];
    this.verbose = verbose;
    this.populateAvailableMethods(clazzName);
  }

  printVerbose(message) {
    if (!this.verbose) { return; }
    this.print(`[v] ${message}`);
  }

  print(message) {
    console.log(message);
  }

  // basically from:
  //  https://github.com/sensepost/objection/blob/fa6a8b8f9b68d6be41b51acb512e6d08754a2f1e/agent/src/android/hooking.ts#L43
  populateAvailableMethods(clazz) {
    this.printVerbose(`Populating available methods...`);
    this.available_methods = this.target.class.getDeclaredMethods().map((method) => {
      var m = method.toGenericString();

      // Remove generics from the method
      while (m.includes("<")) { m = m.replace(/<.*?>/g, ""); }

      // remove any "Throws" the method may have
      if (m.indexOf(" throws ") !== -1) { m = m.substring(0, m.indexOf(" throws ")); }

      // remove scope and return type declarations (aka: first two words)
      // remove the class name
      // remove the signature and return
      m = m.slice(m.lastIndexOf(" "));
      m = m.replace(` ${clazz}.`, "");

      return m.split("(")[0];

    }).filter((value, index, self) => {
      return self.indexOf(value) === index;
    });

    this.printVerbose(`Have ${this.available_methods.length} methods...`);
  }

  validMethod(method) {
    if (!this.available_methods.includes(method)) {
      return false;
    }
    return true;
  }

  isHookingMethod(method) {
    if (this.hooking.map(element => {
      if (element.method == method) { return true; }
      return false;
    }).includes(true)) {
      return true;
    } else {
      return false;
    };
  }

  hook(m, f = null) {
    if (!this.validMethod(m)) {
      this.print(`Method ${m} is not valid for this class.`);
      return;
    }
    if (this.isHookingMethod(m)) {
      this.print(`Already hooking ${m}. Bailing`);
      return;
    }

    this.printVerbose(`Hookig ${m} and all overloads...`);

    var r = [];
    this.target[m].overloads.forEach(overload => {
      if (f == null) {
        overload.replacement = function () {
          return overload.apply(this, arguments);
        }
      } else {
        overload.implementation = function () {
          var ret = overload.apply(this, arguments);
          return f(arguments, ret);
        }
      }

      r.push(overload);
    });

    this.hooking.push({ method: m, replacements: r });
  }

  unhook(method) {
    if (!this.validMethod(method)) {
      this.print(`Method ${method} is not valid for this class.`);
      return;
    }
    if (!this.isHookingMethod(method)) {
      this.print(`Not hooking ${method}. Bailing`);
      return;
    }

    const hooking = this.hooking.filter(element => {
      if (element.method == method) {
        this.printVerbose(`Reverting replacement hook from ${method}`);
        element.replacements.forEach(r => {
          r.implementation = null;
        });
        return; // effectively removing it
      }
      return element;
    });

    this.hooking = hooking;
  }
}

// SAMPLE Usage:

// var replace = function(args, ret) {
//   // be sure to check the args, you may have an overloaded method
//   console.log('Hello from our new function body!');
//   console.log(JSON.stringify(args));
//   console.log(ret);

//   return ret;
// }

// Java.perform(function () {
//   const hook = new JavaHookManager('okhttp3.Request');
//   hook.hook('header', replace);
//   // hook.unhook('header');
// });
