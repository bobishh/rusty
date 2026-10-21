const statuses = new Set(["Removal pending", "Not checked", "Syncing", "Catching up", "Sync paused", "Access required", "Response rejected", "Unavailable", "Synced", "Check overdue"])

export function statusMessageMatches(event, request, now) {
  return Boolean(request && now < request.expiresAt && event.source === request.source && event.origin === request.frontendOrigin &&
    event.data?.type === "rusty-status@1" && event.data.requestId === request.requestId && event.data.origin === request.origin)
}

export function readStatusReply(value, request, now) {
  if (!Number.isSafeInteger(value.checkedAt) || value.checkedAt < request.expiresAt - 120_000 || value.checkedAt > now + 5000 ||
      !Array.isArray(value.boards) || value.boards.length > 128) throw new Error("Invalid board status response")
  const seen = new Set()
  const boards = value.boards.map(board => {
    if (!board || typeof board.id !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(board.id) || seen.has(board.id) ||
        typeof board.title !== "string" || board.title.length > 512 || !statuses.has(board.status) ||
        !["read-only", "read-write", "not-confirmed"].includes(board.access) || (board.lastSyncedAt !== undefined &&
        (!Number.isSafeInteger(board.lastSyncedAt) || board.lastSyncedAt <= 0 || board.lastSyncedAt > value.checkedAt))) throw new Error("Invalid board status response")
    seen.add(board.id)
    return { id: board.id, title: board.title, status: board.status, access: board.access,
      ...(board.lastSyncedAt ? { lastSyncedAt: board.lastSyncedAt } : {}) }
  })
  return { checkedAt: value.checkedAt, boards }
}

function frontendOrigin(value) {
  try {
    const url = new URL(value)
    const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)
    return url.origin === value && !url.username && !url.password && (url.protocol === "https:" || (local && url.protocol === "http:"))
  } catch { return false }
}

function setup() {
  const select = document.querySelector("#frontend-origin")
  const inspect = document.querySelector("#inspect-boards")
  const notice = document.querySelector("#board-notice")
  const listing = document.querySelector("#board-status-list")
  const checked = document.querySelector("#board-checked")
  const origins = JSON.parse(document.querySelector("#frontend-origins").textContent).filter(frontendOrigin)
  for (const origin of origins) {
    const option = document.createElement("option")
    option.value = origin; option.textContent = origin; select.append(option)
  }
  inspect.disabled = !origins.length
  select.closest("label").hidden = origins.length < 2
  if (!origins.length) notice.textContent = "The server operator must configure a Tincanban website in RUSTY_CORS_ORIGINS before board inspection is available."
  let pending, timer
  const finish = () => { clearInterval(timer); pending = undefined; inspect.disabled = !origins.length }
  inspect.addEventListener("click", () => {
    const requestId = Array.from(crypto.getRandomValues(new Uint8Array(16)), byte => byte.toString(16).padStart(2, "0")).join("")
    const request = { origin: location.origin, requestId, expiresAt: Date.now() + 120_000 }
    const target = new URL("/", select.value)
    target.hash = new URLSearchParams({ "rusty-status": JSON.stringify(request) }).toString()
    const source = window.open(target, "_blank")
    if (!source) { notice.textContent = "Allow the Tincanban window to open, then retry."; return }
    pending = { ...request, frontendOrigin: select.value, source }
    inspect.disabled = true
    notice.textContent = "Confirm which board statuses to share in Tincanban."
    timer = setInterval(() => {
      if (pending && (source.closed || Date.now() >= pending.expiresAt)) {
        notice.textContent = source.closed ? "Board inspection cancelled. Your previous results are unchanged." : "Confirmation expired. Retry board inspection."
        source.close(); finish()
      }
    }, 1000)
  })
  window.addEventListener("message", event => {
    if (!statusMessageMatches(event, pending, Date.now())) return
    try {
      const snapshot = readStatusReply(event.data, pending, Date.now())
      const appOrigin = pending.frontendOrigin
      listing.replaceChildren(...snapshot.boards.map(board => renderBoard(board, appOrigin)))
      checked.textContent = `Checked from this browser: ${new Date(snapshot.checkedAt).toLocaleString()}. Refresh to check again.`
      notice.textContent = snapshot.boards.length ? "" : "No boards in this browser are configured on this Rusty server. Open a board in Tincanban and connect it through Sync."
      inspect.textContent = "Refresh board status"
      pending.source.close(); finish()
    } catch { notice.textContent = "Board status could not be read. Retry from Tincanban."; pending.source.close(); finish() }
  })
  window.addEventListener("pagehide", () => { pending?.source.close(); finish() }, { once: true })
  void checkService()
  document.querySelector("#check-service").addEventListener("click", () => { void checkService() })
}

function renderBoard(board, origin) {
  const article = document.createElement("article")
  article.className = "keeper-card board-status"
  article.setAttribute("aria-label", board.title || "Untitled board")
  const title = document.createElement("h3"); title.textContent = board.title || "Untitled board"
  const state = document.createElement("p"); state.textContent = board.status
  const access = document.createElement("p"); access.textContent = board.access === "read-only" ? "Read-only access" : board.access === "read-write" ? "Read and write access" : "Access not confirmed"
  article.append(title, state)
  if (board.status === "Synced") article.append(access)
  if (board.lastSyncedAt) {
    const synced = document.createElement("p"); synced.textContent = `Last confirmed sync: ${new Date(board.lastSyncedAt).toLocaleString()}`; article.append(synced)
  }
  if (board.status === "Access required") {
    const help = document.createElement("p"); help.textContent = "Ask the board owner to reconnect this board through Sync in Tincanban."; article.append(help)
  }
  if (board.status === "Sync paused") {
    const help = document.createElement("p"); help.textContent = "Review the saved connection in Tincanban → Sync."; article.append(help)
  }
  const link = document.createElement("a")
  link.className = "button"; link.textContent = "Open board"
  link.href = new URL(`/boards/${encodeURIComponent(board.id)}`, origin).href
  article.append(link)
  return article
}

async function checkService() {
  const label = document.querySelector("#service-availability")
  label.textContent = "Checking storage…"
  try {
    const response = await fetch("/health", { cache: "no-store", signal: AbortSignal.timeout(5000) })
    const health = await response.json()
    if (!response.ok || health.status !== "ok") throw new Error("Storage unavailable")
    label.textContent = "Storage available"
  } catch { label.textContent = "Storage unavailable. Retry the server check." }
}

if (typeof document !== "undefined") setup()
