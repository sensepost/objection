import { ping } from "./generic/ping";
import { android } from "./rpc/android";
import { cstom } from "./rpc/custom";
import { env } from "./rpc/environment";
import { ios } from "./rpc/ios";
import { jobs } from "./rpc/jobs";
import { memory } from "./rpc/memory";

rpc.exports = {
  ...android,
  ...ios,
  ...env,
  ...jobs,
  ...memory,
  ...cstom,
  ping: (): boolean => ping(),
};
