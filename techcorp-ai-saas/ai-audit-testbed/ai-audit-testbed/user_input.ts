export function getUserInput(req: any): string {
  return req.body.prompt;
}
