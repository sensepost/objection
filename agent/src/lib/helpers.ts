import util from "util";
import { colors as c } from "./color";

// sure, TS does not support this, but meh.
// https://www.reddit.com/r/typescript/comments/87i59e/beginner_advice_strongly_typed_function_for/
export function reverseEnumLookup<T>(enumType: T, value: string): string | undefined {
  for (const key in enumType) {

    if (Object.hasOwnProperty.call(enumType, key) && enumType[key] as any === value) {
      return key;
    }
  }

  return undefined;
}

// converts a hexstring to a bytearray
export const hexStringToBytes = (str: string): Uint8Array => {
  const a = [];
  for (let i = 0, len = str.length; i < len; i += 2) {
    a.push(parseInt(str.substr(i, 2), 16));
  }

  return new Uint8Array(a);
};

// only send if quiet is not true
export const qsend = (quiet: boolean, message: any): void => {
  if (quiet === false) {
    send(message);
   }
};

// a small helper method to use util to dump
export const debugDump = (o: any, depth: number = 2): void => {
  c.log(c.blackBright("\n[start debugDump]"));
  c.log(util.inspect(o, true, depth, true));
  c.log(c.blackBright("[end debugDump]\n"));
};
