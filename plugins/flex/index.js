rpc.exports = {
  initFlex: function (dlib) {

    const NSDocumentDirectory = 9;
    const NSUserDomainMask = 1
    const p = ObjC.classes.NSFileManager.defaultManager()
      .URLsForDirectory_inDomains_(NSDocumentDirectory, NSUserDomainMask).lastObject().path();

    ObjC.schedule(ObjC.mainQueue, function () {
      const libFlexModule = Module.load(p + '/' + dlib);
      const libFlexPtr = libFlexModule.findExportByName("OBJC_CLASS_$_libFlex");
      const libFlex = new ObjC.Object(libFlexPtr);

      libFlex.alloc().init().flexUp();
    });
  }
}
