import * as custom from "../generic/custom";
import * as http from "../generic/http";

export const other = {
  evaluate: (js: string): void => custom.evaluate(js),

  // http server
  httpServerStart: (p: string, port: number): void => http.start(p, port),
  httpServerStatus: (): void => http.status(),
  httpServerStop: (): void => http.stop(),
};
