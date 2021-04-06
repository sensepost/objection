// Frida Objective-C hooking helper class.
//
// Edit the example below the HookManager class to suit your
// needs and then run with:
//  frida -U "App Name" --runtime=v8 -l objchookmanager.js
//
// Generated using objection:
//  https://github.com/sensepost/objection

class ObjCHookManager {

  // create a new Hook for clazzName, specifying if we
  // want verbose logging of this class' internals.
  constructor(clazzName, verbose = false) {
    this.printVerbose(`Booting ObjCHookManager for ${clazzName}...`);

    this.target = ObjC.classes[clazzName];
    // store hooked methods as { method: x, listener: y }
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

  populateAvailableMethods(clazz) {
    this.printVerbose(`Populating available methods...`);
    this.available_methods = ObjC.classes[clazz].$ownMethods;
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

  hook(m, enter = null, leave = null) {
    if (!this.validMethod(m)) {
      this.print(`Method ${m} is not valid for this class.`);
      return;
    }
    if (this.isHookingMethod(m)) {
      this.print(`Already hooking ${m}. Bailing`);
      return;
    }

    this.printVerbose(`Hookig ${m}...`);

    const l = Interceptor.attach(this.target[m].implementation, {
      onEnter: function (args) {
        if (enter != null) {
          enter(args);
        }
      },
      onLeave: function (retval) {
        if (leave != null) {
          leave(retval);
        }
      },
    });

    this.hooking.push({ method: m, listener: l });
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
        this.printVerbose(`Detaching hook from ${method}`);
        element.listener.detach();
        return; // effectively removing it
      }
      return element;
    });

    this.hooking = hooking;
  }
}

// SAMPLE Usage:

// const hook = new ObjCHookManager('NSURLSession');

// // Define the logic to use when entering / leaving
// // the target method.
// const enter = function(args) {
//   console.log(`Entered method.`);
// }
// const leave = function(retval) {
//   console.log(`Method done. Retval was ${retval}`);
// }

// hook.hook('- downloadTaskWithRequest:completionHandler:', enter, leave);
// hook.unhook('- downloadTaskWithRequest:completionHandler:');
