// Agent-domain rule of the .viz registry.
export const VIZ_DOMAIN_LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

/** 2-label sovereign or 3-label delegated agent domain, e.g. `stu.smc.viz`. */
export function isValidVizAgentDomain(value: unknown): value is string {
  if (typeof value !== "string") return false;
  if (value.length === 0 || value.length > 253) return false;
  const parts = value.split(".");
  if (parts.length !== 2 && parts.length !== 3) return false;
  if (parts[parts.length - 1] !== "viz") return false;
  return parts.slice(0, -1).every((p) => VIZ_DOMAIN_LABEL_RE.test(p));
}

/** Label rule the registry's redeem route applies to `name`. */
export const INVITE_LABEL_RE = /^[a-z0-9][a-z0-9-]{0,19}$/;
export const INVITE_NAMESPACE = "z";
export const INVITE_CODE_RE = /^zvi_[A-Za-z0-9_-]{43}$/;
export const INVITE_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const PUBLIC_KEY_HEX_RE = /^[0-9a-fA-F]{64}$/;

/**
 * A free name is `<chosen>-NNNN.<namespace>.viz` and ZipViz assigns the four
 * digits on redeem. `--name` carries the chosen part only; `-NNNN` spends 5 of the 20
 * characters INVITE_LABEL_RE allows, so the chosen part caps at 15.
 */
export const INVITE_CHOSEN_NAME_MAX = 15;
/** A chosen part may not already end in the assigned form, which would mint look-alikes. */
export const INVITE_ASSIGNED_SUFFIX_RE = /-[0-9]{4}$/;

/** Matches the only domain the registry may return for `chosen`: `<chosen>-NNNN.<ns>.viz`. */
export function assignedInviteDomainRe(chosen: string): RegExp {
  // Safe to interpolate: callers check INVITE_LABEL_RE first, so `chosen` is a-z, 0-9 and '-'.
  return new RegExp(`^${chosen}-[0-9]{4}\\.${INVITE_NAMESPACE}\\.viz$`);
}

/** The label of an assigned domain, e.g. `sophie-4821.z.viz` -> `sophie-4821`. */
export function inviteLabelOf(domain: string): string {
  return domain.slice(0, domain.length - `.${INVITE_NAMESPACE}.viz`.length);
}

export function inviteDomain(label: string): string {
  return `${label}.${INVITE_NAMESPACE}.viz`;
}

/** ASCII-only lowercase, so no Unicode case mapping can alias a name. */
export function asciiLower(value: string): string {
  return value.replace(/[A-Z]/g, (c) => c.toLowerCase());
}
