import { ping } from "./generic/ping.js";
import { android } from "./rpc/android.js";
import { env } from "./rpc/environment.js";
import { ios } from "./rpc/ios.js";
import { jobs } from "./rpc/jobs.js";
import { memory } from "./rpc/memory.js";
import { other } from "./rpc/other.js";

rpc.exports = {
  ...android,
  ...ios,
  ...env,
  ...jobs,
  ...memory,
  ...other,
  ping: (): boolean => ping(),
};
