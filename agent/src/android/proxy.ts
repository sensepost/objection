import Java from "frida-java-bridge";
import { wrapJavaPerform } from "./lib/libjava.js";
import { colors as c } from "../lib/color.js";

export const set = (host: string, port: string): Promise<void> => {
  return wrapJavaPerform(() => {
    var proxyHost = host;
    var proxyPort = port;

    var System = Java.use("java.lang.System");

    if (System != undefined) {
      send(c.green(`Setting properties for a proxy`));
      System.setProperty("http.proxyHost", proxyHost);
      System.setProperty("http.proxyPort", proxyPort);

      System.setProperty("https.proxyHost", proxyHost);
      System.setProperty("https.proxyPort", proxyPort);

      send(`${c.green(`Proxy configured to ` + proxyHost + ` ` + proxyPort)}`);
    }
  });
};
