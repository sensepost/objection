import { hooking } from "../native/hooking";
export const native = {
    nativeSearch: (query: string): ApiResolverMatch[] => hooking.search(query),
};
  