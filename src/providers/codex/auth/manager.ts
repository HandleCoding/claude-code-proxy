import { CLIENT_ID, ISSUER, REFRESH_MARGIN_MS } from "./constants.ts"
import { extractAccountId, type TokenResponse } from "./jwt.ts"
import { loadAuthSet, saveAuthSet, type StoredAuthAccount, type StoredAuthSet } from "./token-store.ts"
import { codexProxy } from "../../../config.ts"

function validateTokenResponse(t: unknown): asserts t is TokenResponse {
  if (!t || typeof t !== "object") throw new Error("Invalid token response: not an object")
  const o = t as Record<string, unknown>
  if (typeof o.access_token !== "string" || !o.access_token)
    throw new Error("Invalid token response: missing access_token")
  if (typeof o.refresh_token !== "string" || !o.refresh_token)
    throw new Error("Invalid token response: missing refresh_token")
  if (o.expires_in !== undefined && (typeof o.expires_in !== "number" || !Number.isFinite(o.expires_in) || o.expires_in <= 0))
    throw new Error("Invalid token response: bad expires_in")
}

let cached: StoredAuthSet | undefined
const inflight = new Map<string, Promise<StoredAuthAccount>>()

function accountLabel(account: StoredAuthAccount): string {
  return account.accountId || account.id
}

function newAccountId(accountId?: string): string {
  return accountId || crypto.randomUUID()
}

async function loadRequiredSet(): Promise<StoredAuthSet> {
  if (!cached) {
    const stored = await loadAuthSet()
    if (!stored || stored.accounts.length === 0) {
      throw new Error("Not authenticated. Run: claude-code-proxy codex auth login")
    }
    cached = stored
  }
  return cached
}

async function persistCached(): Promise<void> {
  if (!cached) return
  await saveAuthSet(cached)
}

function updateCachedAccount(account: StoredAuthAccount): void {
  if (!cached) return
  const index = cached.accounts.findIndex((item) => item.id === account.id)
  if (index >= 0) cached.accounts[index] = account
}

export async function getAuth(excludeIds: Set<string> = new Set()): Promise<StoredAuthAccount> {
  const set = await loadRequiredSet()
  const now = Date.now()
  const total = set.accounts.length
  for (let offset = 0; offset < total; offset++) {
    const index = (set.nextIndex + offset) % total
    const account = set.accounts[index]
    if (!account || excludeIds.has(account.id)) continue
    if (account.cooldownUntil && account.cooldownUntil > now) continue
    set.nextIndex = (index + 1) % total
    account.lastUsed = now
    await persistCached()
    if (account.expires - REFRESH_MARGIN_MS > now) return account
    return forceRefresh(account.id)
  }
  throw new Error("No available Codex accounts")
}

export async function forceRefresh(accountId: string): Promise<StoredAuthAccount> {
  const set = await loadRequiredSet()
  const account = set.accounts.find((item) => item.id === accountId)
  if (!account) throw new Error("Codex account not found")
  const existing = inflight.get(account.id)
  if (existing) return existing
  const next = refreshNow(account).finally(() => {
    inflight.delete(account.id)
  })
  inflight.set(account.id, next)
  return next
}

export async function markAccountUnavailable(accountId: string, retryAfter?: string): Promise<void> {
  const set = await loadRequiredSet()
  const account = set.accounts.find((item) => item.id === accountId)
  if (!account) return
  const retryAfterMs = parseRetryAfterMs(retryAfter)
  account.cooldownUntil = Date.now() + (retryAfterMs ?? 60_000)
  await persistCached()
}

function parseRetryAfterMs(retryAfter?: string): number | undefined {
  if (!retryAfter) return undefined
  if (/^\s*\d+(?:\.\d+)?\s*$/.test(retryAfter)) return Math.ceil(Number.parseFloat(retryAfter) * 1000)
  const dateMs = Date.parse(retryAfter) - Date.now()
  return Number.isNaN(dateMs) || dateMs <= 0 ? undefined : Math.ceil(dateMs)
}

async function refreshNow(current: StoredAuthAccount): Promise<StoredAuthAccount> {
  const proxyUrl = codexProxy()
  const fetchOpts: RequestInit & { proxy?: string } = {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: current.refresh,
      client_id: CLIENT_ID,
    }).toString(),
    ...(proxyUrl ? { proxy: proxyUrl } : {}),
  }
  const resp = await fetch(`${ISSUER}/oauth/token`, fetchOpts as RequestInit)
  if (!resp.ok) throw new Error(`Token refresh failed: ${resp.status}`)
  const tokens = await resp.json()
  validateTokenResponse(tokens)
  const accountId = extractAccountId(tokens) || current.accountId
  const next: StoredAuthAccount = {
    id: current.id,
    access: tokens.access_token,
    refresh: tokens.refresh_token || current.refresh,
    expires: Date.now() + (tokens.expires_in ?? 3600) * 1000,
    accountId,
    lastUsed: current.lastUsed,
    cooldownUntil: current.cooldownUntil,
  }
  updateCachedAccount(next)
  await persistCached()
  return next
}

export async function persistInitialTokens(tokens: TokenResponse): Promise<StoredAuthAccount> {
  validateTokenResponse(tokens)
  const accountId = extractAccountId(tokens)
  const auth: StoredAuthAccount = {
    id: newAccountId(accountId),
    access: tokens.access_token,
    refresh: tokens.refresh_token,
    expires: Date.now() + (tokens.expires_in ?? 3600) * 1000,
    accountId,
  }
  const stored = (await loadAuthSet()) ?? { version: 2, accounts: [], nextIndex: 0 }
  const existingIndex = stored.accounts.findIndex((account) => accountLabel(account) === accountLabel(auth))
  if (existingIndex >= 0) {
    auth.id = stored.accounts[existingIndex]?.id ?? auth.id
    stored.accounts[existingIndex] = auth
  } else {
    stored.accounts.push(auth)
  }
  await saveAuthSet(stored)
  cached = stored
  return auth
}

export function resetCache(): void {
  cached = undefined
}
