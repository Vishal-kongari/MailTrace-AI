import { createHash, randomUUID } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { Router, type IRouter, type Request } from "express";
import { and, desc, eq, ilike, or, sql } from "drizzle-orm";
import { db } from "@workspace/db";
import {
  activityTable,
  emailsTable,
  investigationsTable,
  reportsTable,
} from "@workspace/db";
import {
  AnalyzeEmailParams,
  CreateInvestigationBody,
  CreateReportBody,
  GetEmailParams,
  GetEmailAuthenticationParams,
  GetEmailDomainsParams,
  GetEmailGeolocationParams,
  GetEmailGraphParams,
  GetEmailHeadersParams,
  GetEmailIpsParams,
  GetEmailRelayTraceParams,
  GetEmailStatusParams,
  GetEmailUrlsParams,
  GetInvestigationParams,
  ListEmailsQueryParams,
  UpdateInvestigationBody,
  UpdateInvestigationParams,
} from "@workspace/api-zod";

const router: IRouter = Router();
const evidenceDir = path.join(process.cwd(), "data", "mailtrace");

type Header = { name: string; value: string };
type Finding = {
  id: string;
  title: string;
  detail: string;
  severity: string;
  source: string;
};
type UrlIndicator = {
  value: string;
  domain: string;
  source: string;
  status: string;
};
type DomainIndicator = { value: string; source: string; status: string };
type IpIndicator = {
  value: string;
  source: string;
  status: string;
  country: string | null;
  asn: string | null;
};
type RelayHop = { position: number; value: string; source: string };

function getRawBody(req: Request): Buffer {
  if (Buffer.isBuffer(req.body)) return req.body;
  if (typeof req.body === "string") return Buffer.from(req.body);
  return Buffer.alloc(0);
}

function parseHeaders(raw: string): {
  headers: Header[];
  body: string;
} {
  const separator = raw.search(/\r?\n\r?\n/);
  const headerText = separator === -1 ? raw : raw.slice(0, separator);
  const body = separator === -1 ? "" : raw.slice(separator).replace(/^\r?\n\r?\n/, "");
  const unfolded: string[] = [];
  for (const line of headerText.split(/\r?\n/)) {
    if (/^[ \t]/.test(line) && unfolded.length > 0) {
      unfolded[unfolded.length - 1] += ` ${line.trim()}`;
    } else {
      unfolded.push(line);
    }
  }
  return {
    headers: unfolded
      .map((line) => {
        const colon = line.indexOf(":");
        return colon === -1
          ? null
          : { name: line.slice(0, colon).trim(), value: line.slice(colon + 1).trim() };
      })
      .filter((item): item is Header => item !== null),
    body,
  };
}

function firstHeader(headers: Header[], name: string): string | null {
  return headers.find((header) => header.name.toLowerCase() === name.toLowerCase())?.value ?? null;
}

function allHeaders(headers: Header[], name: string): string[] {
  return headers
    .filter((header) => header.name.toLowerCase() === name.toLowerCase())
    .map((header) => header.value);
}

function extractAddress(value: string | null): string {
  if (!value) return "Unknown sender";
  const match = value.match(/<([^>]+)>/);
  return (match?.[1] ?? value).trim();
}

function extractDomain(address: string): string | null {
  return address.match(/@([^>\s]+)/)?.[1]?.toLowerCase() ?? null;
}

function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}

function analyzeEmail(
  headers: Header[],
  body: string,
  sender: string,
  replyTo: string | null,
) {
  const combined = `${headers.map((header) => `${header.name}: ${header.value}`).join("\n")}\n${body}`;
  const lower = combined.toLowerCase();
  const senderDomain = extractDomain(sender);
  const replyDomain = extractDomain(extractAddress(replyTo));
  const urls = unique(
    [...combined.matchAll(/\bhttps?:\/\/[^\s<>"')]+/gi)].map((match) => match[0].replace(/[.,;]+$/, "")),
  );
  const urlIndicators: UrlIndicator[] = urls.map((value) => {
    let domain = "unresolved";
    try {
      domain = new URL(value).hostname.toLowerCase();
    } catch {
      // Keep an explicit unresolved value instead of inventing an enrichment result.
    }
    const suspicious = /(?:login|verify|secure|account|password|invoice|payment)/i.test(value);
    return {
      value,
      domain,
      source: "Extracted from uploaded email",
      status: suspicious ? "review" : "observed",
    };
  });
  const domains = unique(
    [
      ...urlIndicators.map((item) => item.domain),
      ...[...combined.matchAll(/\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b/gi)].map(
        (match) => match[1].toLowerCase(),
      ),
    ].filter((value) => value !== "unresolved"),
  ).map<DomainIndicator>((value) => ({
    value,
    source: "Extracted from uploaded email",
    status: /(?:xn--|\.zip$|\.top$|\.click$|\.gq$)/i.test(value) ? "review" : "observed",
  }));
  const ips = unique(
    [...combined.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)].map((match) => match[0]),
  ).map<IpIndicator>((value) => ({
    value,
    source: "Extracted from uploaded email",
    status: "unavailable",
    country: null,
    asn: null,
  }));
  const received = allHeaders(headers, "Received");
  const relayTrace: RelayHop[] = received.map((value, index) => ({
    position: index + 1,
    value,
    source: "Received header",
  }));
  const auth = firstHeader(headers, "Authentication-Results") ?? "";
  const authentication = {
    spf: /spf=(pass|fail|softfail|neutral|none)/i.exec(auth)?.[1] ?? "unavailable",
    dkim: /dkim=(pass|fail|neutral|none)/i.exec(auth)?.[1] ?? "unavailable",
    dmarc: /dmarc=(pass|fail|bestguesspass|none)/i.exec(auth)?.[1] ?? "unavailable",
    source: auth ? "Authentication-Results header" : "No Authentication-Results header present",
  };
  const findings: Finding[] = [];
  const addFinding = (title: string, detail: string, severity: string, source: string) =>
    findings.push({ id: randomUUID(), title, detail, severity, source });
  if (replyDomain && senderDomain && replyDomain !== senderDomain) {
    addFinding(
      "Reply-To domain differs from sender",
      `Sender domain ${senderDomain} does not match reply-to domain ${replyDomain}.`,
      "high",
      "Parsed sender and Reply-To headers",
    );
  }
  if (authentication.dmarc === "fail" || authentication.spf === "fail" || authentication.dkim === "fail") {
    addFinding(
      "Email authentication failed",
      `Observed SPF ${authentication.spf}, DKIM ${authentication.dkim}, and DMARC ${authentication.dmarc}.`,
      "high",
      "Authentication-Results header",
    );
  }
  if (urlIndicators.some((item) => item.status === "review")) {
    addFinding(
      "Credential or payment URL detected",
      "A URL contains a credential, account, verification, invoice, or payment path.",
      "high",
      "URL extracted from uploaded email",
    );
  }
  if (/(urgent|immediately|within \d+ hours|act now|suspend|verify your account)/i.test(lower)) {
    addFinding(
      "Urgency language detected",
      "The message contains language that pressures the recipient to act quickly.",
      "medium",
      "Language analysis of uploaded email",
    );
  }
  if (/(password|passcode|one[- ]time code|credit card|bank account|wire transfer|gift card)/i.test(lower)) {
    addFinding(
      "Sensitive information request detected",
      "The message references credentials, financial information, or transfer instructions.",
      "high",
      "Language analysis of uploaded email",
    );
  }
  const score = Math.min(
    100,
    findings.reduce((total, finding) => total + (finding.severity === "high" ? 24 : 12), 0) +
      Math.min(urlIndicators.length * 4, 16),
  );
  const threatType =
    score >= 70 ? "Likely phishing" : score >= 35 ? "Needs review" : "No strong signal";
  const confidence = findings.length === 0 ? 0.42 : Math.min(0.96, 0.54 + findings.length * 0.09);
  const graph = buildGraph(sender, domains, urlIndicators, ips, relayTrace);
  return {
    urls: urlIndicators,
    domains,
    ips,
    relayTrace,
    authentication,
    findings,
    riskScore: score,
    threatType,
    confidence,
    graph,
  };
}

function buildGraph(
  sender: string,
  domains: DomainIndicator[],
  urls: UrlIndicator[],
  ips: IpIndicator[],
  relayTrace: RelayHop[],
) {
  const nodes = [{ id: "email", label: "Uploaded email", type: "email" }];
  const edges: Array<{ source: string; target: string; relation: string }> = [];
  const senderId = `sender:${sender}`;
  nodes.push({ id: senderId, label: sender, type: "sender" });
  edges.push({ source: "email", target: senderId, relation: "sent by" });
  domains.forEach((domain) => {
    const id = `domain:${domain.value}`;
    nodes.push({ id, label: domain.value, type: "domain" });
    edges.push({ source: "email", target: id, relation: "mentions" });
  });
  urls.forEach((url) => {
    const id = `url:${url.value}`;
    nodes.push({ id, label: url.value, type: "url" });
    edges.push({ source: "email", target: id, relation: "contains" });
  });
  ips.forEach((ip) => {
    const id = `ip:${ip.value}`;
    nodes.push({ id, label: ip.value, type: "ip" });
    edges.push({ source: "email", target: id, relation: "references" });
  });
  relayTrace.forEach((hop) => {
    const id = `relay:${hop.position}`;
    nodes.push({ id, label: `Relay ${hop.position}`, type: "relay" });
    edges.push({ source: "email", target: id, relation: "relayed through" });
  });
  return { nodes, edges };
}

function serializeEmail(email: typeof emailsTable.$inferSelect) {
  return {
    id: email.id,
    subject: email.subject,
    sender: email.sender,
    receivedAt: email.receivedAt?.toISOString() ?? null,
    analysisStatus: email.analysisStatus,
    riskScore: email.riskScore ?? null,
    threatType: email.threatType ?? null,
    confidence: email.confidence ?? null,
    createdAt: email.createdAt.toISOString(),
  };
}

function createPdf(lines: string[]): Buffer {
  const safeLines = lines.map((line) =>
    line
      .replace(/[^\x20-\x7e]/g, "?")
      .replace(/\\/g, "\\\\")
      .replace(/\(/g, "\\(")
      .replace(/\)/g, "\\)"),
  );
  const content = [
    "BT",
    "/F1 10 Tf",
    "50 760 Td",
    ...safeLines.map((line, index) =>
      index === 0 ? `(${line}) Tj` : `0 -16 Td (${line}) Tj`,
    ),
    "ET",
  ].join("\n");
  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    `<< /Length ${Buffer.byteLength(content, "utf8")} >>\nstream\n${content}\nendstream`,
  ];
  let pdf = "%PDF-1.4\n";
  const offsets = [0];
  objects.forEach((object, index) => {
    offsets[index + 1] = Buffer.byteLength(pdf, "utf8");
    pdf += `${index + 1} 0 obj\n${object}\nendobj\n`;
  });
  const xrefOffset = Buffer.byteLength(pdf, "utf8");
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  pdf += offsets
    .slice(1)
    .map((offset) => `${String(offset).padStart(10, "0")} 00000 n `)
    .join("\n");
  pdf += `\ntrailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`;
  return Buffer.from(pdf, "utf8");
}

async function recordActivity(label: string, detail: string, tone = "neutral") {
  await db.insert(activityTable).values({
    id: randomUUID(),
    label,
    detail,
    tone,
  });
}

async function findEmail(id: string) {
  return db.query.emailsTable.findFirst({ where: eq(emailsTable.id, id) });
}

router.get("/dashboard/stats", async (_req, res) => {
  const [total, highRisk, investigations, indicators] = await Promise.all([
    db.select({ count: sql<number>`count(*)` }).from(emailsTable),
    db.select({ count: sql<number>`count(*)` }).from(emailsTable).where(sql`${emailsTable.riskScore} >= 70`),
    db
      .select({ count: sql<number>`count(*)` })
      .from(investigationsTable)
      .where(eq(investigationsTable.status, "open")),
    db
      .select({
        count: sql<number>`coalesce(sum(jsonb_array_length(coalesce(${emailsTable.urls}, '[]'::jsonb)) + jsonb_array_length(coalesce(${emailsTable.domains}, '[]'::jsonb)) + jsonb_array_length(coalesce(${emailsTable.ips}, '[]'::jsonb))), 0)`,
      })
      .from(emailsTable),
  ]);
  res.json({
    totalEmails: Number(total[0]?.count ?? 0),
    highRiskEmails: Number(highRisk[0]?.count ?? 0),
    openInvestigations: Number(investigations[0]?.count ?? 0),
    extractedIndicators: Number(indicators[0]?.count ?? 0),
    lastUpdated: new Date().toISOString(),
  });
});

router.get("/dashboard/activity", async (_req, res) => {
  const rows = await db.select().from(activityTable).orderBy(desc(activityTable.timestamp)).limit(20);
  res.json(rows.map((row) => ({ ...row, timestamp: row.timestamp.toISOString() })));
});

router.get("/emails", async (req, res) => {
  const params = ListEmailsQueryParams.parse(req.query);
  const rows = await db
    .select()
    .from(emailsTable)
    .where(
      params.search
        ? or(ilike(emailsTable.subject, `%${params.search}%`), ilike(emailsTable.sender, `%${params.search}%`))
        : undefined,
    )
    .orderBy(desc(emailsTable.createdAt))
    .limit(params.limit ?? 25);
  res.json(rows.map(serializeEmail));
});

router.post("/emails/upload", async (req, res) => {
  const buffer = getRawBody(req);
  if (buffer.length === 0) return res.status(400).json({ error: "Upload an .eml, .msg, or .txt file." });
  const raw = buffer.toString("utf8");
  const { headers, body } = parseHeaders(raw);
  const sender = extractAddress(firstHeader(headers, "From"));
  const recipient = firstHeader(headers, "To");
  const replyTo = firstHeader(headers, "Reply-To");
  const subject = firstHeader(headers, "Subject") ?? "(no subject)";
  const dateHeader = firstHeader(headers, "Date");
  const receivedAt = dateHeader ? new Date(dateHeader) : null;
  const messageId = firstHeader(headers, "Message-ID");
  const id = randomUUID();
  const sha256 = createHash("sha256").update(buffer).digest("hex");
  const analysis = analyzeEmail(headers, body, sender, replyTo);
  await mkdir(evidenceDir, { recursive: true });
  const rawPath = path.join(evidenceDir, `${id}.eml`);
  await writeFile(rawPath, buffer, { mode: 0o600 });
  const [email] = await db
    .insert(emailsTable)
    .values({
      id,
      messageId,
      sender,
      recipient,
      replyTo,
      subject,
      body,
      receivedAt: receivedAt && !Number.isNaN(receivedAt.getTime()) ? receivedAt : null,
      rawObjectPath: rawPath,
      sha256,
      analysisStatus: "complete",
      riskScore: analysis.riskScore,
      threatType: analysis.threatType,
      confidence: analysis.confidence,
      authentication: analysis.authentication,
      headers,
      urls: analysis.urls,
      domains: analysis.domains,
      ips: analysis.ips,
      relayTrace: analysis.relayTrace,
      geolocation: [],
      graph: analysis.graph,
      findings: analysis.findings,
    })
    .returning();
  await recordActivity(
    "Email analyzed",
    `${subject} produced ${analysis.findings.length} evidence-backed finding${analysis.findings.length === 1 ? "" : "s"}.`,
    analysis.riskScore >= 70 ? "danger" : "info",
  );
  return res.status(201).json({
    ...serializeEmail(email),
    recipient: email.recipient,
    replyTo: email.replyTo,
    messageId: email.messageId,
    body: email.body,
    sha256: email.sha256,
    findings: analysis.findings,
  });
});

router.get("/emails/:id", async (req, res) => {
  const params = GetEmailParams.parse(req.params);
  const email = await findEmail(params.id);
  if (!email) return res.status(404).json({ error: "Email not found" });
  return res.json({
    ...serializeEmail(email),
    recipient: email.recipient,
    replyTo: email.replyTo,
    messageId: email.messageId,
    body: email.body,
    sha256: email.sha256,
    findings: email.findings ?? [],
  });
});

router.post("/emails/:id/analyze", async (req, res) => {
  const params = AnalyzeEmailParams.parse(req.params);
  const email = await findEmail(params.id);
  if (!email) return res.status(404).json({ error: "Email not found" });
  const analysis = analyzeEmail((email.headers ?? []) as Header[], email.body, email.sender, email.replyTo);
  const [updated] = await db
    .update(emailsTable)
    .set({
      ...analysis,
      analysisStatus: "complete",
    })
    .where(eq(emailsTable.id, email.id))
    .returning();
  await recordActivity("Analysis refreshed", `${email.subject} was analyzed again.`, "info");
  return res.json({
    ...serializeEmail(updated),
    recipient: updated.recipient,
    replyTo: updated.replyTo,
    messageId: updated.messageId,
    body: updated.body,
    sha256: updated.sha256,
    findings: updated.findings ?? [],
  });
});

router.get("/emails/:id/status", async (req, res) => {
  const params = GetEmailStatusParams.parse(req.params);
  const email = await findEmail(params.id);
  if (!email) return res.status(404).json({ error: "Email not found" });
  return res.json({ id: email.id, analysisStatus: email.analysisStatus, progress: email.analysisStatus === "complete" ? 100 : 50 });
});

router.get("/emails/:id/headers", async (req, res) => {
  const params = GetEmailHeadersParams.parse(req.params);
  const email = await findEmail(params.id);
  if (!email) return res.status(404).json({ error: "Email not found" });
  return res.json(email.headers ?? []);
});

router.get("/emails/:id/authentication", async (req, res) => {
  const params = GetEmailAuthenticationParams.parse(req.params);
  const email = await findEmail(params.id);
  if (!email) return res.status(404).json({ error: "Email not found" });
  return res.json(email.authentication ?? { spf: "unavailable", dkim: "unavailable", dmarc: "unavailable", source: "No stored result" });
});

router.get("/emails/:id/urls", async (req, res) => {
  const params = GetEmailUrlsParams.parse(req.params);
  const email = await findEmail(params.id);
  if (!email) return res.status(404).json({ error: "Email not found" });
  return res.json(email.urls ?? []);
});

router.get("/emails/:id/domains", async (req, res) => {
  const params = GetEmailDomainsParams.parse(req.params);
  const email = await findEmail(params.id);
  if (!email) return res.status(404).json({ error: "Email not found" });
  return res.json(email.domains ?? []);
});

router.get("/emails/:id/ips", async (req, res) => {
  const params = GetEmailIpsParams.parse(req.params);
  const email = await findEmail(params.id);
  if (!email) return res.status(404).json({ error: "Email not found" });
  return res.json(email.ips ?? []);
});

router.get("/emails/:id/relay-trace", async (req, res) => {
  const params = GetEmailRelayTraceParams.parse(req.params);
  const email = await findEmail(params.id);
  if (!email) return res.status(404).json({ error: "Email not found" });
  return res.json(email.relayTrace ?? []);
});

router.get("/emails/:id/geolocation", async (req, res) => {
  const params = GetEmailGeolocationParams.parse(req.params);
  const email = await findEmail(params.id);
  if (!email) return res.status(404).json({ error: "Email not found" });
  return res.json(email.geolocation ?? []);
});

router.get("/emails/:id/graph", async (req, res) => {
  const params = GetEmailGraphParams.parse(req.params);
  const email = await findEmail(params.id);
  if (!email) return res.status(404).json({ error: "Email not found" });
  return res.json(email.graph ?? { nodes: [], edges: [] });
});

router.get("/findings", async (_req, res) => {
  const rows = await db.select({ findings: emailsTable.findings }).from(emailsTable);
  return res.json(rows.flatMap((row) => row.findings ?? []));
});

router.get("/investigations", async (_req, res) => {
  const rows = await db.select().from(investigationsTable).orderBy(desc(investigationsTable.updatedAt));
  return res.json(rows.map((row) => ({ ...row, createdAt: row.createdAt.toISOString(), updatedAt: row.updatedAt.toISOString(), emailIds: row.emailIds ?? [] })));
});

router.post("/investigations", async (req, res) => {
  const body = CreateInvestigationBody.parse(req.body);
  const now = new Date();
  const [row] = await db
    .insert(investigationsTable)
    .values({
      id: randomUUID(),
      title: body.title,
      notes: body.notes ?? null,
      priority: body.priority ?? "medium",
      emailIds: body.emailIds ?? [],
      createdAt: now,
      updatedAt: now,
    })
    .returning();
  await recordActivity("Investigation created", body.title, "info");
  return res.status(201).json({ ...row, createdAt: row.createdAt.toISOString(), updatedAt: row.updatedAt.toISOString(), emailIds: row.emailIds ?? [] });
});

router.get("/investigations/:id", async (req, res) => {
  const params = GetInvestigationParams.parse(req.params);
  const [row] = await db.select().from(investigationsTable).where(eq(investigationsTable.id, params.id));
  if (!row) return res.status(404).json({ error: "Investigation not found" });
  return res.json({ ...row, createdAt: row.createdAt.toISOString(), updatedAt: row.updatedAt.toISOString(), emailIds: row.emailIds ?? [] });
});

router.patch("/investigations/:id", async (req, res) => {
  const params = UpdateInvestigationParams.parse(req.params);
  const body = UpdateInvestigationBody.parse(req.body);
  const [row] = await db
    .update(investigationsTable)
    .set({ ...body, updatedAt: new Date() })
    .where(eq(investigationsTable.id, params.id))
    .returning();
  if (!row) return res.status(404).json({ error: "Investigation not found" });
  return res.json({ ...row, createdAt: row.createdAt.toISOString(), updatedAt: row.updatedAt.toISOString(), emailIds: row.emailIds ?? [] });
});

router.post("/reports", async (req, res) => {
  const body = CreateReportBody.parse(req.body);
  const email = await findEmail(body.emailId);
  if (!email) return res.status(404).json({ error: "Email not found" });
  const id = randomUUID();
  const [report] = await db
    .insert(reportsTable)
    .values({
      id,
      emailId: email.id,
      status: "ready",
      downloadUrl: `/api/reports/${id}/download`,
    })
    .returning();
  await recordActivity("Report generated", `Forensic report created for ${email.subject}.`, "info");
  return res.status(201).json({ ...report, createdAt: report.createdAt.toISOString() });
});

router.get("/reports/:id/download", async (req, res) => {
  const [report] = await db.select().from(reportsTable).where(eq(reportsTable.id, req.params.id));
  if (!report) return res.status(404).send("Report not found");
  const email = await findEmail(report.emailId);
  if (!email) return res.status(404).send("Email not found");
  const lines = [
    "MAILTRACE AI FORENSIC REPORT",
    `Subject: ${email.subject}`,
    `Sender: ${email.sender}`,
    `Risk score: ${email.riskScore ?? "unavailable"}/100`,
    `Threat type: ${email.threatType ?? "unavailable"}`,
    `SHA-256: ${email.sha256}`,
    "",
    "FINDINGS",
    ...((email.findings ?? []) as Finding[]).map((finding) => `- [${finding.severity}] ${finding.title}: ${finding.detail}`),
    "",
    "SOURCE",
    "Generated from the uploaded email and persisted analysis results.",
  ];
  return res
    .type("application/pdf")
    .set("Content-Disposition", `attachment; filename="mailtrace-${email.id}.pdf"`)
    .send(createPdf(lines));
});

export default router;