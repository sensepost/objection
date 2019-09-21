import { ping } from "./generic/ping";
import { android } from "./rpc/android";
import { env } from "./rpc/environment";
import { ios } from "./rpc/ios";
import { jobs } from "./rpc/jobs";
import { memory } from "./rpc/memory";
import { other } from "./rpc/other";

rpc.exports = {
  ...android,
  ...ios,
  ...env,
  ...jobs,
  ...memory,
  ...other,
  ping: (): boolean => ping(),
};
