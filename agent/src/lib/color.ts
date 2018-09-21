export namespace colors {

  const base: string = `\x1B[%dm`;
  const reset: string = `\x1b[39m`;

  export const black: number = 30;
  export const blue: number = 34;
  export const cyan: number = 36;
  export const green: number = 92;
  export const magenta: number = 35;
  export const red: number = 31;
  export const white: number = 37;
  export const yellow: number = 33;
  export const blackBright: number = 90;
  export const redBright: number = 91;
  export const greenBright: number = 92;
  export const yellowBright: number = 93;
  export const blueBright: number = 94;
  export const magentaBright: number = 95;
  export const cyanBright: number = 96;
  export const whiteBright: number = 97;

  const colorArray: number[] = [
    blue, cyan, green, magenta, red, yellow,
    redBright, greenBright, yellowBright, blueBright, magentaBright, cyanBright,
  ];
  export const randc = (): number => colorArray[Math.floor(Math.random() * colorArray.length)];

  // return an ansified string
  export const ansifyString = (color: number, ...msg: string[]): string =>
    base.replace(`%d`, color.toString()) + msg.join(``) + reset;

  // tslint:disable-next-line:no-console
  export const log = (color: number, ...msg: string[]): void => console.log(ansifyString(color, ...msg));
}
