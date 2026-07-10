import { marked } from "marked";

// 1. Convert README.md (English) to index.html
const markdown = await Deno.readTextFile("README.md");
const htmlBody = await marked(markdown);
const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WebAuthn P256 Public Key Index</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/github-markdown-css/5.8.1/github-markdown-light.min.css">
<style>
  * { box-sizing: border-box; }
  html { background: #f6f8fa; }
  body {
    max-width: 980px;
    margin: 40px auto;
    padding: 40px 48px;
    background: #fff;
    border: 1px solid #d0d7de;
    border-radius: 6px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.04);
  }
  .markdown-body {
        margin: 40px auto !important;
  }
  .markdown-body { font-size: 16px; line-height: 1.7; }
  @media (max-width: 767px) {
    body { margin: 16px; padding: 24px 16px; }
  }
</style>
</head>
<body class="markdown-body">
<div style="text-align:right;margin-bottom:16px">
  <a href="https://github.com/mondaylabsltd/p256-index" target="_blank" style="color:#24292f;text-decoration:none;font-size:14px">
    <svg height="20" width="20" viewBox="0 0 16 16" style="vertical-align:middle;margin-right:4px;fill:currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>GitHub
  </a>
</div>
${htmlBody}</body>
</html>`;
await Deno.writeTextFile("deno/index.html", html);
console.log("Generated deno/index.html");

// 2. Compile to binary
const cmd = new Deno.Command("deno", {
  args: [
    "compile",
    "--include", "deno/index.html",
    "--allow-net", "--allow-read", "--allow-write", "--allow-env", "--allow-ffi",
    "--output", "dist/webauthnp256-publickey-index",
    "deno/index.ts",
  ],
  stdout: "inherit",
  stderr: "inherit",
});
const { code } = await cmd.output();
if (code !== 0) {
  Deno.exit(1);
}
console.log("Build complete");
