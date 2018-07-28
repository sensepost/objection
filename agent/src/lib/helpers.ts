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
