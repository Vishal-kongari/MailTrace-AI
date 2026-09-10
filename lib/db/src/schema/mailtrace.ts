import { createInsertSchema } from "drizzle-zod";
import {
  integer,
  jsonb,
  pgTable,
  real,
  text,
  timestamp,
} from "drizzle-orm/pg-core";
import { z } from "zod/v4";

export const emailsTable = pgTable("mailtrace_emails", {
  id: text("id").primaryKey(),
  messageId: text("message_id"),
  sender: text("sender").notNull().default("Unknown sender"),
  recipient: text("recipient"),
  replyTo: text("reply_to"),
  subject: text("subject").notNull().default("(no subject)"),
  body: text("body").notNull().default(""),
  receivedAt: timestamp("received_at", { withTimezone: true }),
  rawObjectPath: text("raw_object_path"),
  sha256: text("sha256").notNull(),
  analysisStatus: text("analysis_status").notNull().default("complete"),
  riskScore: real("risk_score"),
  threatType: text("threat_type"),
  confidence: real("confidence"),
  authentication: jsonb("authentication").$type<{
    spf: string;
    dkim: string;
    dmarc: string;
    source: string;
  }>(),
  headers: jsonb("headers").$type<Array<{ name: string; value: string }>>(),
  urls: jsonb("urls").$type<
    Array<{ value: string; domain: string; source: string; status: string }>
  >(),
  domains: jsonb("domains").$type<
    Array<{ value: string; source: string; status: string }>
  >(),
  ips: jsonb("ips").$type<
    Array<{
      value: string;
      source: string;
      status: string;
      country: string | null;
      asn: string | null;
    }>
  >(),
  relayTrace: jsonb("relay_trace").$type<
    Array<{ position: number; value: string; source: string }>
  >(),
  geolocation: jsonb("geolocation").$type<
    Array<{
      ip: string;
      country: string | null;
      city: string | null;
      latitude: number | null;
      longitude: number | null;
      source: string;
    }>
  >(),
  graph: jsonb("graph").$type<{
    nodes: Array<{ id: string; label: string; type: string }>;
    edges: Array<{ source: string; target: string; relation: string }>;
  }>(),
  findings: jsonb("findings").$type<
    Array<{
      id: string;
      title: string;
      detail: string;
      severity: string;
      source: string;
    }>
  >(),
  createdAt: timestamp("created_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

export const investigationsTable = pgTable("mailtrace_investigations", {
  id: text("id").primaryKey(),
  title: text("title").notNull(),
  status: text("status").notNull().default("open"),
  priority: text("priority").notNull().default("medium"),
  notes: text("notes"),
  emailIds: text("email_ids").array().notNull().default([]),
  createdAt: timestamp("created_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

export const reportsTable = pgTable("mailtrace_reports", {
  id: text("id").primaryKey(),
  emailId: text("email_id").notNull(),
  status: text("status").notNull().default("ready"),
  createdAt: timestamp("created_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
  downloadUrl: text("download_url").notNull(),
});

export const activityTable = pgTable("mailtrace_activity", {
  id: text("id").primaryKey(),
  label: text("label").notNull(),
  detail: text("detail").notNull(),
  tone: text("tone").notNull().default("neutral"),
  timestamp: timestamp("timestamp", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

export const insertEmailSchema = createInsertSchema(emailsTable);
export const insertInvestigationSchema = createInsertSchema(investigationsTable);
export const insertReportSchema = createInsertSchema(reportsTable);
export const insertActivitySchema = createInsertSchema(activityTable);

export type EmailRecord = typeof emailsTable.$inferSelect;
export type InvestigationRecord = typeof investigationsTable.$inferSelect;
export type ReportRecord = typeof reportsTable.$inferSelect;
export type ActivityRecord = typeof activityTable.$inferSelect;

export const emailIdSchema = z.string().min(1);
export const investigationIdSchema = z.string().min(1);