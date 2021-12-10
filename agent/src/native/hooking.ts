export namespace hooking{
    export const search = (query: string): ApiResolverMatch[] => {
        const resolver = new ApiResolver('module')
        return resolver.enumerateMatches(query)
    }
}