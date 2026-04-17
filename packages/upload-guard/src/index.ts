import { createHash } from "node:crypto";
import type { UploadVerdict } from "@aegis/contracts";

const MIME_BY_EXTENSION: Record<string, string> = {
  ".csv": "text/csv",
  ".json": "application/json",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".pdf": "application/pdf",
  ".png": "image/png",
  ".txt": "text/plain"
};

export function sanitizeFilename(filename: string): string {
  const normalized = filename
    .replace(/[/\\]+/g, "-")
    .replace(/\.\.+/g, ".")
    .replace(/[^A-Za-z0-9._-]+/g, "_")
    .slice(0, 120);

  return normalized || "upload.bin";
}

export function sniffMime(buffer: Buffer): string {
  if (buffer.subarray(0, 4).equals(Buffer.from([0x25, 0x50, 0x44, 0x46]))) {
    return "application/pdf";
  }

  if (
    buffer
      .subarray(0, 8)
      .equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))
  ) {
    return "image/png";
  }

  if (buffer.subarray(0, 3).equals(Buffer.from([0xff, 0xd8, 0xff]))) {
    return "image/jpeg";
  }

  if (
    buffer.every(
      (byte) => byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126)
    )
  ) {
    return "text/plain";
  }

  return "application/octet-stream";
}

export function evaluateUpload(input: {
  filename: string;
  declaredMime: string;
  content: Buffer;
  maxBytes: number;
  allowedExtensions?: string[];
}): UploadVerdict {
  const normalizedFilename = sanitizeFilename(input.filename);
  const lower = normalizedFilename.toLowerCase();
  const lastDot = lower.lastIndexOf(".");
  const extension = lastDot >= 0 ? lower.slice(lastDot) : "";
  const detectedMime = sniffMime(input.content);
  const allowedExtensions = input.allowedExtensions ?? Object.keys(MIME_BY_EXTENSION);
  const flags: string[] = [];

  if (input.content.byteLength > input.maxBytes) {
    return {
      accepted: false,
      reason: "File exceeds configured size limit.",
      normalizedFilename,
      detectedMime,
      size: input.content.byteLength,
      flags: ["size-limit"]
    };
  }

  if (normalizedFilename.split(".").length > 3) {
    flags.push("double-extension");
  }

  if (!allowedExtensions.includes(extension)) {
    return {
      accepted: false,
      reason: "Extension is not allowlisted.",
      normalizedFilename,
      detectedMime,
      size: input.content.byteLength,
      flags: [...flags, "extension-rejected"]
    };
  }

  const expectedMime = MIME_BY_EXTENSION[extension];
  if (expectedMime && detectedMime !== "application/octet-stream" && detectedMime !== expectedMime) {
    return {
      accepted: false,
      reason: "Declared content does not match detected MIME.",
      normalizedFilename,
      detectedMime,
      size: input.content.byteLength,
      flags: [...flags, "mime-mismatch"]
    };
  }

  if (input.declaredMime && input.declaredMime !== detectedMime && detectedMime !== "text/plain") {
    flags.push("declared-mime-mismatch");
  }

  return {
    accepted: true,
    reason: "Upload accepted into quarantine for downstream processing.",
    normalizedFilename,
    detectedMime,
    size: input.content.byteLength,
    sha256: createHash("sha256").update(input.content).digest("hex"),
    flags
  };
}

