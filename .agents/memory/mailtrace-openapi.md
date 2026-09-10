---
name: MailTrace API upload contract
description: Why the first-build upload endpoint uses a raw octet stream instead of multipart in this Node workspace.
---

The MailTrace upload contract intentionally accepts `application/octet-stream` as a string body, while the client sends the selected file bytes. Multipart binary schemas make the generated Node-side Zod package reference browser-only `File` and `Blob` globals at runtime.

**Why:** The generated server validation package is shared with the Express service, so browser-only multipart types can break server compilation or module evaluation.

**How to apply:** If multipart support is restored later, keep the server runtime schema browser-safe or split browser upload validation from server schemas before changing the OpenAPI body shape.