import sc = require("frida-screenshot");

export namespace userinterface {

  export const screenshot = (): any => {
    // heavy lifting thanks to frida-screenshot!
    // https://github.com/nowsecure/frida-screenshot
    return sc();
  };
}
