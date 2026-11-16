export function handleRules () {
    const targetTypes : TargetType[] = ["domain", "wildcard", "ip", "cidr", "url_prefix"]
    const rules : Rule[] = [
        {targetType: "domain", effect: "include", pattern: "example.com"},
        {targetType: "wildcard", effect: "include", pattern: "*.example.com"},
        {targetType: "ip", effect: "exclude", pattern: "203.0.113.5"},
        {targetType: "cidr", effect: "exclude", pattern: "198.51.100.0/24"},
        {targetType: "url_prefix", effect: "exclude", pattern: "https://example.com/admin"}
    ]

    return rules
}

// export function parseRules (rules: string) {
//     const s = rules.split("\n")

//     return s.map(rule => {
//         const [targetType, effect, pattern] = rule.split(" ")
//         return {
//             targetType,
//             effect,
//             pattern
//         }
//     })
// }