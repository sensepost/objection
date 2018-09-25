export namespace colors {

  const base: string = `\x1B[%dm`;
  const reset: string = `\x1b[39m`;

  export const black = (message: string) => ansify(30, message);
  export const blue = (message: string) => ansify(34, message);
  export const cyan = (message: string) => ansify(36, message);
  export const green = (message: string) => ansify(32, message);
  export const magenta = (message: string) => ansify(35, message);
  export const red = (message: string) => ansify(31, message);
  export const white = (message: string) => ansify(37, message);
  export const yellow = (message: string) => ansify(33, message);
  export const blackBright = (message: string) => ansify(90, message);
  export const redBright = (message: string) => ansify(91, message);
  export const greenBright = (message: string) => ansify(92, message);
  export const yellowBright = (message: string) => ansify(93, message);
  export const blueBright = (message: string) => ansify(94, message);
  export const cyanBright = (message: string) => ansify(96, message);
  export const whiteBright = (message: string) => ansify(97, message);

  // return an ansified string
  export const ansify = (color: number, ...msg: string[]): string =>
    base.replace(`%d`, color.toString()) + msg.join(``) + reset;

  // tslint:disable-next-line:no-eval
  export const clog = (color: number, ...msg: string[]): void => eval("console").log(ansify(color, ...msg));
  // tslint:disable-next-line:no-eval
  export const log = (...msg: string[]): void => eval("console").log(msg.join(``));
}
