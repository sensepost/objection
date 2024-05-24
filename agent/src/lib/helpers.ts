import util from "util";
import { colors as c } from "./color.js";

// sure, TS does not support this, but meh.
// https://www.reddit.com/r/typescript/comments/87i59e/beginner_advice_strongly_typed_function_for/
export function reverseEnumLookup<T>(enumType: T, value: string): string {
  for (const key in enumType) {

    if (Object.hasOwnProperty.call(enumType, key) && enumType[key] as any === value) {
      return key;
    }
  }

  return "";
}

// converts a hexstring to a bytearray
export const hexStringToBytes = (str: string): Uint8Array => {
  var a: number[] = [];
  for (let i = 0, len = str.length; i < len; i += 2) {
    a.push(parseInt(str.substring(i, i+2), 16));
  }

  return new Uint8Array(a);
};

// only send if quiet is not true
export const qsend = (quiet: boolean, message: any): void => {
  if (quiet === false) {
    send(message);
  }
};

// send a preformated dict
export const fsend = (ident: string, hook: string, message: any): void => {
  send(
    c.blackBright(`[${ident}] `) +
    c.magenta(`[${hook}]`) +
    printArgs(message)
  );
};

// a small helper method to use util to dump
export const debugDump = (o: any, depth: number = 2): void => {
  c.log(c.blackBright("\n[start debugDump]"));
  c.log(util.inspect(o, true, depth, true));
  c.log(c.blackBright("[end debugDump]\n"));
};

// a small helper method to format JSON nicely before printing
function printArgs(args: {[key: string]:object}): string {
  let printableString: string = " (\n";
  for (const arg in args) {
    printableString += `  ${c.blue(arg)} : ${args[arg]}\n`;
  }
  printableString += ")";
  return printableString;
}