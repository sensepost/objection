import macho from "macho-ts";

import * as iosfilesystem from "./filesystem.js";
import { IBinaryModuleDictionary } from "./lib/interfaces.js";


const isEncrypted = (cmds: any[]): boolean => {
  for (const cmd of cmds) {
    // https://opensource.apple.com/source/cctools/cctools-921/include/mach-o/loader.h.auto.html
    // struct encryption_info_command {
    //    [ ... ]
    //   uint32_t	cryptid;	/* which enryption system, 0 means not-encrypted yet */
    // };
    if (cmd.type === "encryption_info" || cmd.type === "encryption_info_64") {
      if (cmd.id !== 0) {
        return true;
      }
    }
  }
  return false;
};

export const info = (): IBinaryModuleDictionary => {
  const modules = Process.enumerateModules();
  const parsedModules: IBinaryModuleDictionary = {};

  modules.forEach((a) => {
    if (!a.path.includes(".app")) {
      return;
    }

    const imports: Set<string> = new Set(a.enumerateImports().map((i) => i.name));
    const fb = iosfilesystem.readFile(a.path);
    if (typeof(fb) == 'string') {
      return;
    }

    try {
      const exe = macho.parse(fb);

      parsedModules[a.name] = {
        arc: imports.has("objc_release"),
        canary: imports.has("__stack_chk_fail"),
        encrypted: isEncrypted(exe.cmds),
        pie: exe.flags.pie ? true : false,
        rootSafe: exe.flags.root_safe ? true : false,
        stackExec: exe.flags.allow_stack_execution ? true : false,
        type: exe.filetype,
      };

    } catch (e) {
      // ignore any errors. especially ones where
      // the target path is not a mach-o
    }
  });

  return parsedModules;
};
