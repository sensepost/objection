import { colors as c } from "../lib/color.js";
import { bytesToUTF8 } from "./lib/helpers.js";
import { IHeapObject } from "./lib/interfaces.js";


const enumerateInstances = (clazz: string): ObjC.Object[] => {
  if (!ObjC.classes.hasOwnProperty(clazz)) {
    c.log(`Unknown Objective-C class: ${c.redBright(clazz)}`);
    return [];
  }

  const specifier: ObjC.DetailedChooseSpecifier = {
    class: ObjC.classes[clazz],
    subclasses: true,  // don't skip subclasses
  };

  return ObjC.chooseSync(specifier);
};

export const getInstances = (clazz: string): IHeapObject[] => {
  c.log(`${c.blackBright(`Enumerating live instances of`)} ${c.greenBright(clazz)}...`);
  
  const instances: IHeapObject[] = [];

  enumerateInstances(clazz).map((instance) => {
    try {
      instances.push({
        className: instance.$className,
        handle: instance.handle.toString(),
        ivars: instance.$ivars,
        kind: instance.$kind,
        methods: instance.$ownMethods,
        superClass: instance.$superClass.$className,
      });
    } catch (err) {
      c.log(`Warning: ${c.yellowBright((err as Error).message)}`);
    }
  });

  return instances;
};

const resolvePointer = (pointer: string): ObjC.Object => {
  const o = new ObjC.Object(new NativePointer(pointer));
  c.log(`${c.blackBright(`Pointer ` + pointer + ` is to class `)}${c.greenBright(o.$className)}`);

  return o;
};

export const getIvars = (pointer: string, toUTF8: boolean): [string, any[string]] => {
  const { $className, $ivars } = resolvePointer(pointer);

  // if we need to get utf8 representations, start a new object with
  // which cloned properties will have utf8 values. we _could_ have
  // just gone and replaces values in $ivars, but there are some
  // access errors for that.
  if (toUTF8) {
    const $clonedIvars: {[name: string]: any} = {};
    c.log(c.blackBright(`Converting ivar values to UTF8 strings...`));
    for (const k in $ivars) {
      if ($ivars.hasOwnProperty(k)) {
        const v = $ivars[k];
        $clonedIvars[k] = bytesToUTF8(v);
      }
    }

    return [$className, $clonedIvars];
  }

  return [$className, $ivars];
};

export const getMethods = (pointer: string): [string, any[string]] => {
  const { $className, $ownMethods } = resolvePointer(pointer);
  return [$className, $ownMethods];
};

export const callInstanceMethod = (pointer: string, method: string, returnString: boolean): void => {
  const i = resolvePointer(pointer);
  c.log(`${c.blackBright(`Executing:`)} ${c.greenBright(`[${i.$className} ${method}]`)}`);

  const result = i[method]();

  if (returnString) {
    return result.toString();
  }
  return i[method]();
};

export const evaluate = (pointer: string, js: string): void => {
  const ptr = resolvePointer(pointer);
  // tslint:disable-next-line:no-eval
  eval(js);
};
