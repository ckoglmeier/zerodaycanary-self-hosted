// Presentation only for Canary-generated explanations from older assessments.
// Never apply to uploaded audit text, source excerpts, identifiers or URLs.
export function alertCopy(text: string | null | undefined): string {
  return (text ?? "").split(/(https?:\/\/[^\s<>]+)/g).map((part, index) => index % 2 ? part : part.replace(/\bthis advisory\b/gi, (phrase) => phrase[0] === "T" ? "This vulnerability" : "this vulnerability").replace(/\bthese advisories\b/gi, (phrase) => phrase[0] === "T" ? "These vulnerabilities" : "these vulnerabilities").replace(/\badvisor(?:y|ies)\b/gi, (word) => {
    const replacement = word.toLowerCase() === "advisories" ? "alerts" : "alert";
    return word === word.toUpperCase() ? replacement.toUpperCase() : /^[A-Z]/.test(word) ? replacement[0].toUpperCase() + replacement.slice(1) : replacement;
  })).join("");
}
