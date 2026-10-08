import { AnsError } from "./reasons.js";

/**
 * ANSName from draft-narajala-courtney-ansv2-01 §5.1:
 * `ans://v` version `.` agentHost, version = 1*DIGIT `.` 1*DIGIT `.` 1*DIGIT.
 * The draft also requires a numeric semantic version, an agentHost of at most
 * 237 octets, and a complete ANSName of at most 400 octets.
 */
const NAME_RE = /^[Aa][Nn][Ss]:\/\/v(\d+)\.(\d+)\.(\d+)\.(.+)$/;
const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export type AnsName = {
  name: string;
  version: string;
  major: string;
  minor: string;
  patch: string;
  host: string;
};

function versionPart(value: string): boolean {
  return value === "0" || /^[1-9]\d*$/.test(value);
}

function isDottedQuad(host: string): boolean {
  const parts = host.split(".");
  if (parts.length !== 4) return false;
  return parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

export function parseAnsName(input: string): AnsName {
  if (input.length === 0 || input.length > 400 || input !== input.trim() || /\s/u.test(input)) {
    throw new AnsError("ANS_NAME_INVALID", "ANS name must be ans://v<major>.<minor>.<patch>.<fqdn> and at most 400 octets");
  }
  const match = NAME_RE.exec(input);
  if (!match) {
    throw new AnsError("ANS_NAME_INVALID", "ANS name must be ans://v<major>.<minor>.<patch>.<fqdn>");
  }
  const major = match[1]!;
  const minor = match[2]!;
  const patch = match[3]!;
  const host = match[4]!.toLowerCase();
  if (!versionPart(major) || !versionPart(minor) || !versionPart(patch)) {
    throw new AnsError("ANS_NAME_INVALID", "ANS version must be a numeric major.minor.patch without leading zeros");
  }
  if (host.length > 237) {
    throw new AnsError("ANS_NAME_INVALID", "agentHost exceeds the 237 octet limit");
  }
  if (isDottedQuad(host)) {
    throw new AnsError("ANS_NAME_INVALID", "agentHost must be a domain name");
  }
  const labels = host.split(".");
  if (labels.length < 2 || labels.some((label) => !LABEL_RE.test(label))) {
    throw new AnsError("ANS_NAME_INVALID", "agentHost must be an LDH domain name of at least two labels");
  }
  const version = `${major}.${minor}.${patch}`;
  const name = `ans://v${version}.${host}`;
  if (name.length > 400) {
    throw new AnsError("ANS_NAME_INVALID", "ANS name exceeds the 400 octet limit");
  }
  return { name, version, major, minor, patch, host };
}
