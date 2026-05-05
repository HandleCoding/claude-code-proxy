import { mkdir, readFile, writeFile, unlink, rename } from "node:fs/promises"
import { dirname, join } from "node:path"
import { keychainGet, keychainSet, keychainDelete } from "../../../keychain.ts"
import { configDir, legacyConfigDir } from "../../../paths.ts"

export interface StoredAuth {
  access: string
  refresh: string
  expires: number
  accountId?: string
}

export interface StoredAuthAccount extends StoredAuth {
  id: string
  lastUsed?: number
  cooldownUntil?: number
}

export interface StoredAuthSet {
  version: 2
  accounts: StoredAuthAccount[]
  nextIndex: number
}

function file(): string {
  return join(configDir(), "codex", "auth.json")
}
function legacyFile(): string {
  return join(legacyConfigDir(), "codex", "auth.json")
}
const KEYCHAIN_SERVICE = "claude-code-proxy.codex"
const KEYCHAIN_ACCOUNT = "auth"

function isAuthSet(value: unknown): value is StoredAuthSet {
  const o = value as Partial<StoredAuthSet> | undefined
  return !!o && o.version === 2 && Array.isArray(o.accounts)
}

function legacyToSet(auth: StoredAuth): StoredAuthSet {
  return {
    version: 2,
    accounts: [{ ...auth, id: auth.accountId || "default" }],
    nextIndex: 0,
  }
}

function parseAuthSet(raw: string): StoredAuthSet {
  const parsed = JSON.parse(raw) as StoredAuthSet | StoredAuth
  if (isAuthSet(parsed)) {
    return {
      version: 2,
      accounts: parsed.accounts.map((account, index) => ({
        ...account,
        id: account.id || account.accountId || `account-${index + 1}`,
      })),
      nextIndex: Number.isInteger(parsed.nextIndex) ? parsed.nextIndex : 0,
    }
  }
  return legacyToSet(parsed)
}

function normalizeSet(set: StoredAuthSet): StoredAuthSet {
  return {
    version: 2,
    accounts: set.accounts,
    nextIndex: set.accounts.length === 0 ? 0 : ((set.nextIndex % set.accounts.length) + set.accounts.length) % set.accounts.length,
  }
}

export async function loadAuthSet(): Promise<StoredAuthSet | undefined> {
  if (process.platform === "darwin") {
    const raw = keychainGet(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
    if (!raw) return undefined
    return normalizeSet(parseAuthSet(raw))
  }

  const primary = file()
  try {
    const raw = await readFile(primary, "utf8")
    return normalizeSet(parseAuthSet(raw))
  } catch (err: any) {
    if (err?.code !== "ENOENT") throw err
  }
  const legacy = legacyFile()
  if (legacy === primary) return undefined
  try {
    const raw = await readFile(legacy, "utf8")
    return normalizeSet(parseAuthSet(raw))
  } catch (err: any) {
    if (err?.code === "ENOENT") return undefined
    throw err
  }
}

export async function saveAuthSet(set: StoredAuthSet): Promise<void> {
  const normalized = normalizeSet(set)
  if (process.platform === "darwin") {
    keychainSet(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, JSON.stringify(normalized))
    return
  }

  const path = file()
  await mkdir(dirname(path), { recursive: true, mode: 0o700 })
  const tmp = `${path}.${process.pid}.${Date.now()}.tmp`
  await writeFile(tmp, JSON.stringify(normalized, null, 2), { encoding: "utf8", mode: 0o600 })
  await rename(tmp, path)
}

export async function loadAuth(): Promise<StoredAuth | undefined> {
  const set = await loadAuthSet()
  return set?.accounts[0]
}

export async function saveAuth(auth: StoredAuth): Promise<void> {
  await saveAuthSet(legacyToSet(auth))
}

export async function clearAuth(): Promise<void> {
  if (process.platform === "darwin") {
    keychainDelete(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
    return
  }

  for (const path of [file(), legacyFile()]) {
    try {
      await unlink(path)
    } catch (err: any) {
      if (err?.code !== "ENOENT") throw err
    }
  }
}

export function authPath(): string {
  return process.platform === "darwin" ? "macOS Keychain" : file()
}
