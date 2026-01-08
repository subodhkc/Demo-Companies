export function buildPrompt(userInput: string): string {
  return `SYSTEM: You are an assistant.\nUSER: ${userInput}`;
}
