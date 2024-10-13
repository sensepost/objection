import * as fs from "frida-fs";
import * as httpLib from "http";
import * as url from "url";
import { colors as c } from "../lib/color.js";

let httpServer: httpLib.Server;
let listenPort: number;
let servePath: string;

const log = (m: string): void => {
  c.log(`[http server] ${m}`);
};

const dirListingHTML = (pwd: string, path: string): string => {
  let h = `
    <html>
      <body>
        <h2 style="margin: 0;">Index Of ${path}</h2>
        {file_listing}
      </body>
    </html>
    `;

  h = h.replace(`{file_listing}`, () => {
    return fs.list(pwd + decodeURIComponent(path)).map((f) => {
      if (f.name === '.') return;

      // Add a slash at the end if it is a directory.
      var fname = f.name + (f.type == 4 ? '/' : '');
      
      if (path !== '/') {
        return `<a href="${path + fname}">${fname}</a>`;
      } else if (fname !== '../') {
        return `<a href="${fname}">${fname}</a>`;
      }
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

    try {    
      const parsedUrl = url.parse(req.url);  
      const fileLocation = pwd + decodeURIComponent(parsedUrl.path);
      
      if (fs.statSync(fileLocation).isDirectory()) {
        res.end(dirListingHTML(pwd, parsedUrl.path));
        return;
      }

      res.setHeader("Content-type", "application/octet-stream");

      // Check that we are not reading an empty file
      if (fs.statSync(fileLocation).size !== 0) {
        const file = fs.readFileSync(fileLocation);
        res.write(file, 'utf-8')
      }
      res.end();
        
    } catch (error) {
      if (error instanceof Error && error.message == "No such file or directory") {
        res.statusCode = 404;
        res.end("File not found")
      } else {
        if (error instanceof Error) {
          log(c.redBright(`${error.stack}`));
        } else {
          log(c.redBright(`${error}`));
        }
       
        res.statusCode = 500;
        res.end("Internal Server Error")
      }
    }
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
      httpServer = undefined;
    });
};

export const status = (): void => {
  if (httpServer && httpServer.listening) {
    log(`Server is running on port ` +
      `${c.greenBright(listenPort.toString())} serving ${c.greenBright(servePath)}`);
    return;
  }

  log(c.yellowBright(`Server does not appear to be running.`));
};
