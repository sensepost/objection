import * as fs from "fs";
import * as httpLib from "http";
import * as url from "url";
import { colors as c } from "../lib/color.js";

let httpServer: httpLib.Server;
let listenPort: number;
let servePath: string;

const log = (m: string): void => {
  c.log(`[http server] ${m}`);
};

const dirListingHTML = (p: string): string => {
  let h = `
    <html>
      <body>
        <h2>Index Of /</h2>
        {file_listing}
      </body>
    </html>
    `;

  h = h.replace(`{file_listing}`, () => {
    return fs.readdirSync(p).map((f) => {
      return `<a href="${f}">${f}</a>`;
    }).join("<br>");
  });

  return h;
};

export const start = (pwd: string, port: number = 9000): void => {
  if (httpServer) {
    log(c.redBright(`Server appears to already be running`));
    return;
  }

  if (!pwd.endsWith("/")) {
    pwd = pwd + "/";
  }
  log(`${c.blackBright(`Starting HTTP server in: ${pwd}`)}`);
  servePath = pwd;

  httpServer = httpLib.createServer((req, res) => {
    if (req.method && req.url) {
      log(`${c.greenBright(req.method)} ${req.url}`);
    } else {
      log(`${c.redBright('Missing URL or request method.')}`);
      return;
    }
    
    const parsedUrl =  new URL(req.url);

    if (parsedUrl.pathname === "/") {
      res.end(dirListingHTML(pwd));
      return;
    }

    res.setHeader("Content-type", "application/octet-stream");
    res.end(fs.readFileSync(pwd + parsedUrl.pathname));
  });

  httpServer.listen(port);
  listenPort = port;
};

export const stop = (): void => {
  if (!httpServer) {
    log(c.yellowBright(`Server does not appear to be running.`));
    return;
  }

  log(c.blackBright(`Waiting for client connections to close then stopping...`));
  httpServer.close()
    .once("close", () => {
      log(c.blackBright(`Server closed.`));
      // httpServer = undefined;
    });
};

export const status = (): void => {
  if (httpServer.listening) {
    log(`Server is running on port ` +
      `${c.greenBright(listenPort.toString())} serving ${c.greenBright(servePath)}`);
    return;
  }

  log(c.yellowBright(`Server does not appear to be running.`));
};
