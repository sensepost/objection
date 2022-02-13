export const evaluate = (js: string): void => {
  // tslint:disable-next-line:no-eval
  eval(js);
};
