import * as custom from "../generic/custom.js";
import * as http from "../generic/http.js";

export const other = {
  evaluate: (js: string): void => custom.evaluate(js),

  // http server
  httpServerStart: (p: string, port: number): void => http.start(p, port),
  httpServerStatus: (): void => http.status(),
  httpServerStop: (): void => http.stop(),
};
