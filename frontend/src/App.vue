<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from "vue"
import RustyMark from "./RustyMark.vue"

type Board = {
  workspaceId: string
  title: string
  isPrimary: boolean
  heads: string[]
  peerCount: number
  lastSavedAt?: number | null
  replication?: { state: string; activePeers: number; lastSuccessAt?: number | null; lastErrorCategory?: string | null }
}
type Trigger = {
  errorDetail?: string | null
  id: string
  name: string
  configured: boolean
  model: string
  pendingCount: number
  outcomes: { awaitingMesh: number; chatQueued: number; cardCreated: number }
}
type Overview = {
  keeper: { displayName: string; personId: string; deviceId: string; boards: Board[] }
  triggers: Trigger[]
  replication: { state: string; activePeers: number; lastSuccessAt?: number | null; lastErrorCategory?: string | null }
}
type AdminIdentity = { personId: string | null; displayName: string; operator: boolean }
type CorsSettings = { origins: string[]; requiredOrigin: string }
type Pairing = {
  id: string
  comparisonCode: string
  controller: { displayName: string }
  controllerFingerprint: string
  serviceFingerprint: string
  scopes: { title: string; mode: string }[]
  futureBoards: boolean
  operatorApproved: boolean | null
  controllerApproved: boolean | null
  provisioning?: { status: string; scopes: { workspaceId: string; status: string; error?: string; errorDetail?: string }[] } | null
}

const resetOpen = ref(false)
const resetToken = ref("")
const resetError = ref("")
const resetNotice = ref("")
const resetting = ref(false)
let resetRequestedAt = 0

async function resetKeeper() {
  resetError.value = ""
  resetting.value = true
  try {
    await api("/admin/api/reset", { method: "POST", body: JSON.stringify({ secret: resetToken.value }) })
    resetToken.value = ""
    resetRequestedAt = Date.now()
    resetNotice.value = "Reset requested. Rusty is restarting…"
  } catch (cause) {
    resetting.value = false
    resetError.value = cause instanceof Error ? cause.message : "Could not reset keeper"
  }
}

const csrf = ref("")
const token = ref("")
const signedIn = ref(false)
const adminIdentity = ref<AdminIdentity | null>(null)
const sessionLoading = ref(true)
const sessionUnavailable = ref(false)
const loading = ref(false)
const error = ref("")
const overview = ref<Overview | null>(null)
const pairings = ref<Pairing[]>([])
const pendingPairings = computed(() => pairings.value.filter(pairing =>
  pairing.provisioning?.status !== "active" && pairing.operatorApproved !== false && pairing.controllerApproved !== false))
const corsRequired = ref("")
const corsDraft = ref("")
const corsLoaded = ref(false)
const corsSaving = ref(false)
const corsError = ref("")
const corsNotice = ref("")
const unsubscribeBoard = ref<Board | null>(null)
const unsubscribing = ref(false)
const unsubscribeError = ref("")
const pollIntervalMs = 5_000
let pollTimer: ReturnType<typeof setInterval> | undefined
let refreshInFlight = false
let sessionVersion = 0
const replicationState = computed(() => overview.value?.replication.state ?? "idle")

class ApiError extends Error {
  constructor(message: string, readonly status: number) { super(message) }
}

async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    credentials: "same-origin",
    cache: "no-store",
    ...options,
    headers: {
      "content-type": "application/json",
      ...(csrf.value ? { "x-csrf-token": csrf.value } : {}),
      ...(options.headers ?? {}),
    },
  })
  const value = await response.json().catch(() => ({}))
  if (!response.ok) throw new ApiError(value.message || `Request failed (${response.status})`, response.status)
  return value as T
}

function validMatchLoginUrl(value: string, challengeId: string) {
  const target = new URL(value)
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(target.hostname)
  if (target.username || target.password || target.hash || target.pathname !== "/login" || target.searchParams.size !== 2
    || target.searchParams.get("keeper") !== window.location.origin
    || target.searchParams.get("challenge") !== challengeId
    || (target.protocol !== "https:" && !(loopback && target.protocol === "http:"))) {
    throw new Error("Rusty returned an unsafe Match sign-in link.")
  }
  return target.toString()
}

async function signInWithMatch() {
  error.value = ""
  loading.value = true
  try {
    const response = await api<{ challengeId: string; matchUrl: string }>("/admin/api/login/challenge", {
      method: "POST",
      body: JSON.stringify({}),
    })
    window.location.assign(validMatchLoginUrl(response.matchUrl, response.challengeId))
  } catch (cause) {
    loading.value = false
    error.value = cause instanceof Error ? cause.message : "Could not start Match sign-in."
  }
}

function clearIdentity() {
  sessionVersion++
  csrf.value = ""
  signedIn.value = false
  adminIdentity.value = null
  overview.value = null
  pairings.value = []
  corsLoaded.value = false
  corsDraft.value = ""
}

async function loadCorsSettings() {
  if (!adminIdentity.value?.operator) return
  corsError.value = ""
  try {
    const settings = await api<CorsSettings>("/admin/api/settings/cors")
    corsRequired.value = settings.requiredOrigin
    corsDraft.value = settings.origins.filter(origin => origin !== settings.requiredOrigin).join("\n")
    corsLoaded.value = true
  } catch (cause) {
    corsLoaded.value = false
    corsError.value = cause instanceof Error ? cause.message : "Could not load allowed origins"
  }
}

async function saveCorsSettings() {
  if (!corsLoaded.value || corsSaving.value) return
  corsSaving.value = true
  corsError.value = ""
  corsNotice.value = ""
  try {
    const origins = [corsRequired.value, ...corsDraft.value.split(/\r?\n/).map(origin => origin.trim()).filter(Boolean)]
    const settings = await api<CorsSettings>("/admin/api/settings/cors", {
      method: "POST", body: JSON.stringify({ origins }),
    })
    corsDraft.value = settings.origins.filter(origin => origin !== settings.requiredOrigin).join("\n")
    corsNotice.value = "Allowed origins saved"
  } catch (cause) {
    corsError.value = cause instanceof Error ? cause.message : "Could not save allowed origins"
  } finally {
    corsSaving.value = false
  }
}

async function logout() {
  error.value = ""
  try {
    await api("/admin/api/logout", { method: "POST", body: JSON.stringify({}) })
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : "Could not sign out."
    return
  }
  clearIdentity()
}

async function exchangeLoginCode() {
  const code = new URLSearchParams(window.location.hash.slice(1)).get("login")
  window.history.replaceState(null, "", window.location.pathname + window.location.search)
  if (!code) return false
  sessionLoading.value = true
  error.value = ""
  try {
    const identity = await api<{ csrfToken: string } & AdminIdentity>("/admin/api/login/exchange", {
      method: "POST",
      body: JSON.stringify({ code }),
    })
    csrf.value = identity.csrfToken
    adminIdentity.value = identity
    signedIn.value = true
    await refresh()
    await loadCorsSettings()
  } catch (cause) {
    clearIdentity()
    error.value = cause instanceof Error ? cause.message : "Could not complete Match sign-in."
  } finally {
    sessionLoading.value = false
  }
  return true
}

async function restoreSession() {
  sessionLoading.value = true
  sessionUnavailable.value = false
  error.value = ""
  try {
    const response = await api<{ csrfToken: string } & AdminIdentity>("/admin/api/session")
    csrf.value = response.csrfToken
    adminIdentity.value = response
    signedIn.value = true
    await refresh()
    await loadCorsSettings()
  } catch (cause) {
    if (cause instanceof ApiError && cause.status === 403) {
      clearIdentity()
    } else {
      sessionUnavailable.value = true
      error.value = cause instanceof Error ? cause.message : "Could not check operator session"
    }
  } finally {
    sessionLoading.value = false
  }
}

async function signIn() {
  error.value = ""
  try {
    const response = await api<{ csrfToken: string } & AdminIdentity>("/admin/api/session", {
      method: "POST",
      body: JSON.stringify({ secret: token.value }),
    })
    csrf.value = response.csrfToken
    adminIdentity.value = response
    signedIn.value = true
    sessionUnavailable.value = false
    token.value = ""
    await refresh()
    await loadCorsSettings()
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : "Sign-in failed"
  }
}

async function refresh() {
  if (refreshInFlight || !signedIn.value) return
  if (resetting.value) {
    if (!resetRequestedAt) return
    try { await api("/admin/api/session") }
    catch (cause) {
      if (cause instanceof ApiError && cause.status === 403) {
        clearIdentity()
        resetting.value = false
        resetOpen.value = false
        resetNotice.value = "Keeper reset. Sign in again to add boards."
      }
    }
    if (resetting.value && Date.now() - resetRequestedAt > 60_000) {
      resetNotice.value = "Reset restart not confirmed. Reload Rusty to check status."
    }
    return
  }
  refreshInFlight = true
  const version = sessionVersion
  try {
    const [nextOverview, nextPairings] = await Promise.all([
      api<Overview>("/admin/api/overview"),
      api<{ pairings: Pairing[] }>("/admin/api/pairings"),
    ])
    if (version !== sessionVersion) return
    overview.value = nextOverview
    pairings.value = nextPairings.pairings
    error.value = ""
  } catch (cause) {
    if (version !== sessionVersion) return
    if (cause instanceof ApiError && cause.status === 403) clearIdentity()
    error.value = cause instanceof Error ? cause.message : "Could not load keeper overview"
  } finally {
    refreshInFlight = false
  }
}

function refreshWhenVisible() {
  if (!document.hidden && signedIn.value) void refresh()
}

async function decide(pairing: Pairing, decision: "approve" | "decline") {
  error.value = ""
  try {
    await api(`/admin/api/pairings/${encodeURIComponent(pairing.id)}/decision`, {
      method: "POST",
      body: JSON.stringify({ decision }),
    })
    await refresh()
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : "Decision failed"
  }
}

function date(value?: number | null) {
  if (!value) return "No saved timestamp"
  return new Date(value * 1000).toLocaleString()
}

async function unsubscribe() {
  const board = unsubscribeBoard.value
  if (!board || unsubscribing.value) return
  unsubscribing.value = true
  unsubscribeError.value = ""
  try {
    await api(`/admin/api/boards/${encodeURIComponent(board.workspaceId)}/unsubscribe`, { method: "POST", body: "{}" })
    if (overview.value) overview.value.keeper.boards = overview.value.keeper.boards.filter(value => value.workspaceId !== board.workspaceId)
    unsubscribeBoard.value = null
    await refresh()
  } catch (cause) {
    unsubscribeError.value = cause instanceof Error ? cause.message : "Could not unsubscribe board"
  } finally {
    unsubscribing.value = false
  }
}

function pairingStatus(pairing: Pairing) {
  if (pairing.operatorApproved === false || pairing.controllerApproved === false) return "Keeper request declined. No access granted."
  if (pairing.operatorApproved === null) return "Waiting for keeper operator to approve service access."
  if (pairing.controllerApproved === null) return "Waiting for Match identity confirmation."
  return "Both approvals are recorded. See board rows above for keeper replication status."
}

onMounted(async () => {
  pollTimer = setInterval(refreshWhenVisible, pollIntervalMs)
  document.addEventListener("visibilitychange", refreshWhenVisible)
  if (window.location.hash.startsWith("#login=")) {
    if (await exchangeLoginCode()) return
  }
  await restoreSession()
})

onUnmounted(() => {
  if (pollTimer) clearInterval(pollTimer)
  document.removeEventListener("visibilitychange", refreshWhenVisible)
})

</script>

<template>
  <div class="shell keeper-admin">
    <header class="topbar">
      <div class="brand">
        <RustyMark />
        <div>
          <h1>RUSTY</h1>
        </div>
      </div>
      <div v-if="signedIn" class="admin-header-actions">
        <button class="button button-quiet" type="button" @click="logout">Sign out</button>
      </div>
    </header>

    <main class="admin-content">
      <nav v-if="signedIn" class="admin-nav" aria-label="Keeper sections">
        <a class="button button-small button-quiet" href="#keepers-title">Overview</a><a class="button button-small button-quiet" href="#approvals-title">Approvals<span v-if="pendingPairings.length" class="count-badge">{{ pendingPairings.length }}</span></a><a v-if="adminIdentity?.operator" class="button button-small button-quiet" href="#settings-title">Settings</a>
      </nav>
      <p v-if="sessionLoading" class="empty-state" role="status">Checking operator session…</p>
      <section v-else-if="sessionUnavailable" class="login-card">
        <h2>Session check unavailable</h2>
        <p class="section-copy">Could not reach Rusty. Retry to check your operator session.</p>
        <button class="button button-primary" type="button" @click="restoreSession">Retry session check</button>
      </section>
      <form v-else-if="!signedIn" class="login-card" @submit.prevent="signIn">
        <h2>Sign in</h2>
        <p class="section-copy">Use your Match identity to see boards connected to your account.</p>
        <button class="button button-primary" type="button" :disabled="loading" @click="signInWithMatch">{{ loading ? "Opening Match…" : "Sign in with Match" }}</button>
        <details class="service-admin-fallback">
          <summary>Service administration</summary>
          <p class="section-copy">Operator token grants service-wide approval access.</p>
          <label class="field-label" for="operator-token">Operator token</label>
          <input id="operator-token" v-model="token" type="password" autocomplete="current-password" required />
          <button class="button button-quiet" type="submit">Sign in as operator</button>
        </details>
      </form>

      <p v-if="error" class="admin-notice admin-notice-error" role="status">{{ error }}</p>
      <p v-if="resetNotice" class="admin-notice" role="status">{{ resetNotice }}</p>

      <template v-if="signedIn">
        <section v-if="overview" aria-labelledby="keepers-title" class="admin-section">
          <div class="section-heading">
            <div>
              <h2 id="keepers-title">Keepers</h2>
            </div>
            <p class="replication-status" :data-state="replicationState">Replication {{ replicationState }}</p>
          </div>

          <article class="keeper-card">
            <div class="keeper-heading">
              <div>
                <h3>{{ overview.keeper.displayName }}</h3>
                <p class="muted keeper-identity">{{ overview.keeper.personId }}</p>
              </div>
            </div>

            <div class="overview-grid">
              <section class="overview-group">
                <h4>Boards</h4>
                <p v-if="!overview.keeper.boards.length" class="muted">No attached boards.</p>
                <article v-for="board in overview.keeper.boards" :key="board.workspaceId" class="board-row">
                  <div class="board-title"><strong>{{ board.title }}</strong><span v-if="board.isPrimary" class="muted">(primary board)</span></div>
                  <p>{{ board.peerCount }} authorized peers · {{ board.heads.length }} current heads</p>
                  <p>Saved {{ date(board.lastSavedAt) }} · replication {{ board.replication?.state ?? "idle" }}</p>
                  <p v-if="board.replication?.lastSuccessAt">Last exchange {{ date(board.replication.lastSuccessAt) }}</p>
                  <p v-if="board.replication?.lastErrorCategory" class="muted">Last transport state: {{ board.replication.lastErrorCategory }}</p>
                  <button class="button button-small" type="button" :disabled="unsubscribing" @click="unsubscribeBoard = board; unsubscribeError = ''">Unsubscribe</button>
                  <div v-if="unsubscribeBoard?.workspaceId === board.workspaceId" class="unsubscribe-confirm">
                    <p>Stop replicating {{ board.title }}?</p>
                    <p class="muted">Disconnects this board from Rusty and ends its owner's future-board subscription. Match keeps its copy.</p>
                    <div class="dialog-actions">
                      <button class="button button-small" type="button" :disabled="unsubscribing" @click="unsubscribe">{{ unsubscribing ? 'Unsubscribing…' : 'Confirm unsubscribe' }}</button>
                      <button class="button button-small" type="button" :disabled="unsubscribing" @click="unsubscribeBoard = null">Cancel</button>
                    </div>
                    <p v-if="unsubscribeError" class="admin-notice admin-notice-error" role="alert">{{ unsubscribeError }}</p>
                  </div>
                </article>
              </section>

              <section class="overview-group">
                <h4>Triggers</h4>
                <p v-if="!overview.triggers.length" class="muted">No configured triggers.</p>
                <article v-for="trigger in overview.triggers" :key="trigger.id" class="board-row">
                  <div class="board-title"><strong>{{ trigger.name }}</strong></div>
                  <p v-if="trigger.errorDetail" class="admin-notice admin-notice-error" role="alert">{{ trigger.errorDetail }}</p>
                  <p>{{ trigger.configured ? "Configured" : "Not configured" }} · {{ trigger.pendingCount }} pending · {{ trigger.model }}</p>
                  <p>{{ trigger.outcomes.cardCreated }} cards created · {{ trigger.outcomes.chatQueued }} chats queued · {{ trigger.outcomes.awaitingMesh }} awaiting Match</p>
                </article>
              </section>
            </div>
          </article>
        </section>

        <section aria-labelledby="approvals-title" class="admin-section approvals-section">
          <div class="section-heading">
            <h2 id="approvals-title">Approvals<span v-if="pendingPairings.length"> ({{ pendingPairings.length }})</span></h2>
          </div>
          <p v-if="!pendingPairings.length" class="empty-state">No pending keeper requests. Create one from Match → Sync → Add keeper.</p>
          <article v-for="pairing in pendingPairings" :key="pairing.id" class="approval-card">
            <h3>{{ pairing.controller.displayName }} · {{ pairing.comparisonCode }}</h3>
            <p class="muted">Controller {{ pairing.controllerFingerprint }} · service {{ pairing.serviceFingerprint }}</p>
            <ul><li v-for="scope in pairing.scopes" :key="scope.title">{{ scope.title }} · {{ scope.mode }}</li></ul>
            <p>{{ pairing.futureBoards ? "Future boards included in approval" : "Future boards not included" }}</p>
            <p>Controller approval: {{ pairing.controllerApproved === true ? "approved" : pairing.controllerApproved === false ? "declined" : "pending" }}</p>
            <p v-if="pairing.provisioning">Board setup: {{ pairing.provisioning.status }}</p>
            <p v-for="scope in pairing.provisioning?.scopes.filter(scope => scope.error) ?? []" :key="scope.workspaceId" class="admin-notice admin-notice-error" role="alert">{{ scope.workspaceId }}: {{ scope.errorDetail || scope.error }}</p>
            <div class="dialog-actions">
              <template v-if="adminIdentity?.operator">
                <button class="button button-primary" type="button" :disabled="pairing.operatorApproved !== null || pairing.controllerApproved === false" @click="decide(pairing, 'approve')">Approve exact boards</button>
                <button class="button" type="button" :disabled="pairing.operatorApproved !== null || pairing.controllerApproved === false" @click="decide(pairing, 'decline')">Decline</button>
              </template>
            <p v-else class="muted" role="status">{{ pairingStatus(pairing) }}</p>
            </div>
          </article>
        </section>
        <section v-if="adminIdentity?.operator" aria-labelledby="settings-title" class="admin-section">
          <div class="section-heading"><h2 id="settings-title">Settings</h2></div>
          <form class="keeper-card cors-settings" @submit.prevent="saveCorsSettings">
            <h3>Allowed website origins</h3>
            <p class="section-copy">Match sign-in origin stays enabled. Add other websites allowed to reach Rusty intake, one HTTPS origin per line.</p>
            <p class="muted">Match: {{ corsRequired || "Loading…" }}</p>
            <label class="field-label" for="cors-origins">Additional origins</label>
            <textarea id="cors-origins" v-model="corsDraft" :disabled="!corsLoaded || corsSaving" rows="3" placeholder="https://example.com"></textarea>
            <div class="cors-actions">
              <button class="button button-small button-primary" type="submit" :disabled="!corsLoaded || corsSaving">{{ corsSaving ? "Saving…" : "Save origins" }}</button>
              <button v-if="!corsLoaded" class="button button-small" type="button" @click="loadCorsSettings">Retry loading</button>
            </div>
            <p v-if="corsError" class="admin-notice admin-notice-error" role="alert">{{ corsError }}</p>
            <p v-if="corsNotice" class="admin-notice" role="status">{{ corsNotice }}</p>
          </form>
          <div class="keeper-card danger-zone">
            <h3>Reset keeper</h3>
            <p>Remove all boards, pairing requests, intake messages and JEV results. Rusty keeps its identity and website settings. Match keeps its boards. A private recovery backup stays on the server.</p>
            <button v-if="!resetOpen" class="button button-small" type="button" @click="resetOpen = true; resetError = ''">Reset keeper</button>
            <form v-else @submit.prevent="resetKeeper">
              <label class="field-label" for="reset-token">Reset operator token</label>
              <input id="reset-token" v-model="resetToken" type="password" autocomplete="off" :disabled="resetting" required />
              <div class="dialog-actions">
                <button class="button button-small button-danger" type="submit" :disabled="resetting || !resetToken">{{ resetting ? 'Resetting…' : 'Delete all keeper data' }}</button>
                <button class="button button-small" type="button" :disabled="resetting" @click="resetOpen = false; resetToken = ''">Cancel</button>
              </div>
              <p v-if="resetError" class="admin-notice admin-notice-error" role="alert">{{ resetError }}</p>
            </form>
          </div>
        </section>
      </template>
    </main>
  </div>
</template>
