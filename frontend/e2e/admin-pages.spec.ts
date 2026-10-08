import { expect, test } from "@playwright/test"

async function signedIn(page: import("@playwright/test").Page, operator = true) {
  await page.route("**/admin/api/session", route => route.fulfill({ json: { csrfToken: "csrf", personId: operator ? null : "keeper-person", displayName: operator ? "Operator" : "Keeper", operator } }))
  await page.route("**/admin/api/overview", route => route.fulfill({ json: { keeper: { displayName: "Rusty", personId: "keeper-person", deviceId: "device-1", boards: [{ workspaceId: "board-1", title: "Garden", isPrimary: true, heads: ["head"], peerCount: 2 }] }, triggers: [{ id: "jev", name: "JEV", configured: true, model: "v1", pendingCount: 1, outcomes: { cardCreated: 0, chatQueued: 0, awaitingMesh: 1 } }], replication: { state: "idle", activePeers: 0 } } }))
  await page.route("**/admin/api/pairings", route => route.fulfill({ json: { pairings: [] } }))
  await page.route("**/admin/api/settings/cors", route => route.fulfill({ json: { requiredOrigin: "https://match.example", origins: ["https://match.example"] } }))
}

test("Given operator session, when navigating and reloading routes, then pages follow URL and browser history", async ({ page }) => {
  await signedIn(page)
  await page.goto("/admin/")
  await expect(page.getByRole("heading", { name: "Keepers", exact: true })).toBeVisible()
  await page.getByRole("link", { name: "Open keeper" }).click()
  await expect(page).toHaveURL(/\/admin\/keepers\/keeper-person$/)
  await expect(page.getByRole("heading", { name: "Rusty", exact: true })).toBeVisible()
  await expect(page.getByRole("heading", { name: "Triggers", exact: true })).toBeVisible()
  await page.getByRole("navigation", { name: "Keeper sections" }).getByRole("link", { name: "Keepers", exact: true }).click()
  await expect(page).toHaveURL(/\/admin\/keepers$/)
  await expect(page.getByRole("link", { name: "Open keeper" })).toBeVisible()
  await page.getByRole("link", { name: "Approvals", exact: true }).click()
  await expect(page).toHaveURL(/\/admin\/approvals$/)
  await page.getByRole("link", { name: "Settings", exact: true }).click()
  await expect(page).toHaveURL(/\/admin\/settings$/)
  await page.reload()
  await expect(page.getByRole("heading", { name: "Settings", exact: true })).toBeVisible()
  await page.goBack()
  await expect(page).toHaveURL(/\/admin\/approvals$/)
  await expect(page.getByRole("heading", { name: "Approvals", exact: true })).toBeVisible()
})

test("Given a signed-in admin, when viewing keeper, approval, and settings routes, then user-facing references use Tincanban", async ({ page }) => {
  await signedIn(page)
  await page.goto("/admin/keepers")
  await expect(page.getByText("Keeper services connected to your Tincanban identity.", { exact: true })).toBeVisible()
  await page.getByRole("link", { name: "Open keeper" }).click()
  await expect(page.getByText("0 cards created · 0 chats queued · 1 awaiting Tincanban", { exact: true })).toBeVisible()
  await page.getByRole("link", { name: "Approvals", exact: true }).click()
  await expect(page.getByText("No pending keeper requests. Create one from Tincanban → Sync → Add keeper.", { exact: true })).toBeVisible()
  await page.getByRole("link", { name: "Settings", exact: true }).click()
  await expect(page.getByText("Tincanban sign-in origin stays enabled. Add other websites allowed to reach Rusty intake, one HTTPS origin per line.", { exact: true })).toBeVisible()
  await expect(page.getByText("Tincanban: https://match.example", { exact: true })).toBeVisible()
})

test("Given a keeper awaiting owner confirmation, when opening approvals, then status names Tincanban", async ({ page }) => {
  await page.route("**/admin/api/session", route => route.fulfill({ json: { csrfToken: "csrf", personId: "owner", displayName: "Owner", operator: false } }))
  await page.route("**/admin/api/overview", route => route.fulfill({ json: { keeper: { displayName: "Rusty", personId: "keeper-person", deviceId: "device-1", boards: [] }, triggers: [], replication: { state: "idle", activePeers: 0 } } }))
  await page.route("**/admin/api/pairings", route => route.fulfill({ json: { pairings: [{ id: "pending-1", comparisonCode: "123456", controller: { displayName: "Owner" }, controllerFingerprint: "owner", serviceFingerprint: "keeper", scopes: [{ title: "Garden", mode: "replicate" }], futureBoards: false, operatorApproved: true, controllerApproved: null }] } }))
  await page.goto("/admin/approvals")
  await expect(page.getByText("Waiting for Tincanban identity confirmation.", { exact: false })).toBeVisible()
})

test("Given owner-origin approval, when opening approvals, then Rusty does not request a second operator approval", async ({ page }) => {
  await page.route("**/admin/api/session", route => route.fulfill({ json: { csrfToken: "csrf", personId: "owner", displayName: "Owner", operator: false } }))
  await page.route("**/admin/api/overview", route => route.fulfill({ json: { keeper: { displayName: "Rusty", personId: "keeper-person", deviceId: "device-1", boards: [] }, triggers: [], replication: { state: "idle", activePeers: 0 } } }))
  await page.route("**/admin/api/pairings", route => route.fulfill({ json: { pairings: [{ id: "owner-origin-1", comparisonCode: "123456", controller: { displayName: "Owner" }, controllerFingerprint: "owner", serviceFingerprint: "keeper", scopes: [{ title: "Garden", mode: "replicate" }], futureBoards: false, operatorApproved: true, controllerApproved: true, admissionSource: "owner_origin" }] } }))
  await page.goto("/admin/approvals")
  await expect(page.getByRole("status")).toContainText("Owner approved this request from an allowed origin.")
  await expect(page.getByRole("status")).toContainText("Rusty is preparing the selected boards.")
  await expect(page.getByText("Waiting for keeper operator to approve service access.", { exact: true })).toHaveCount(0)
})

test("Given cancellation cleanup is pending, when Rusty confirms completion, then only unresolved cancellation stays in approvals", async ({ page }) => {
  let withdrawalStatus: "cancel_pending" | "cancelled" = "cancel_pending"
  await page.route("**/admin/api/session", route => route.fulfill({ json: { csrfToken: "csrf", personId: null, displayName: "Operator", operator: true } }))
  await page.route("**/admin/api/overview", route => route.fulfill({ json: { keeper: { displayName: "Rusty", personId: "keeper-person", deviceId: "device-1", boards: [] }, triggers: [], replication: { state: "idle", activePeers: 0 } } }))
  await page.route("**/admin/api/pairings", route => route.fulfill({ json: { pairings: [
    { id: "cancel-pending", comparisonCode: "111111", controller: { displayName: "Owner" }, controllerFingerprint: "owner", serviceFingerprint: "keeper", scopes: [{ workspaceId: "board-1", title: "Garden", mode: "replicate" }], futureBoards: false, operatorApproved: true, controllerApproved: true, withdrawalStatus, provisioning: { status: withdrawalStatus === "cancel_pending" ? "pending_cleanup" : "detached", scopes: [] } },
    { id: "active-history", comparisonCode: "222222", controller: { displayName: "Owner" }, controllerFingerprint: "owner", serviceFingerprint: "keeper", scopes: [{ workspaceId: "board-1", title: "Garden", mode: "replicate" }], futureBoards: false, operatorApproved: true, controllerApproved: true, provisioning: { status: "active", scopes: [{ workspaceId: "board-1", status: "active" }] } },
    { id: "detached-history", comparisonCode: "333333", controller: { displayName: "Owner" }, controllerFingerprint: "owner", serviceFingerprint: "keeper", scopes: [{ workspaceId: "board-1", title: "Garden", mode: "replicate" }], futureBoards: false, operatorApproved: true, controllerApproved: true, provisioning: { status: "detached", scopes: [] } },
  ] } }))
  await page.route("**/admin/api/settings/cors", route => route.fulfill({ json: { requiredOrigin: "https://match.example", origins: ["https://match.example"] } }))
  await page.goto("/admin/approvals")

  const pendingCard = page.locator(".approval-card").filter({ hasText: "111111" })
  await expect(page.getByRole("link", { name: "Approvals (1)" })).toBeVisible()
  await expect(pendingCard.getByRole("status")).toContainText("Cancellation pending. Rusty is completing cleanup; approval is unavailable.")
  await expect(pendingCard.getByRole("button", { name: "Approve exact boards" })).toHaveCount(0)
  await expect(pendingCard.getByRole("button", { name: "Decline" })).toHaveCount(0)
  await expect(page.locator(".approval-card")).toHaveCount(1)

  withdrawalStatus = "cancelled"
  await page.reload()
  await expect(page.getByRole("heading", { name: "Approvals" })).toBeVisible()
  await expect(page.getByText("No pending keeper requests. Create one from Tincanban → Sync → Add keeper.", { exact: true })).toBeVisible()
  await expect(page.locator(".approval-card")).toHaveCount(0)
  await expect(page.getByRole("link", { name: /Approvals/ })).toHaveText("Approvals")
})

test("Given owner session, when opening operator settings URL, then route returns to keepers", async ({ page }) => {
  await signedIn(page, false)
  await page.goto("/admin/settings")
  await expect(page).toHaveURL(/\/admin\/keepers$/)
  await expect(page.getByRole("link", { name: "Settings" })).toHaveCount(0)
})

test("Given an unknown keeper, when opening its deep link, then recovery link stays available", async ({ page }) => {
  await signedIn(page)
  await page.goto("/admin/keepers/missing")
  await expect(page.getByRole("heading", { name: "Keeper unavailable", exact: true })).toBeVisible()
  await page.reload()
  await page.getByRole("link", { name: "Back to keepers" }).click()
  await expect(page).toHaveURL(/\/admin\/keepers$/)
  await page.evaluate(() => {
    window.history.pushState(null, "", "/admin/keepers/%E0%A4%A")
    window.dispatchEvent(new PopStateEvent("popstate"))
  })
  await expect(page.getByRole("heading", { name: "Keeper unavailable", exact: true })).toBeVisible()
})

test("Given a pending approval, when decision fails then retry succeeds, then request remains actionable until saved", async ({ page }) => {
  let saved = false
  let attempts = 0
  await page.route("**/admin/api/session", route => route.fulfill({ json: { csrfToken: "csrf", personId: null, displayName: "Operator", operator: true } }))
  await page.route("**/admin/api/overview", route => route.fulfill({ json: { keeper: { displayName: "Rusty", personId: "keeper-person", deviceId: "device-1", boards: [] }, triggers: [], replication: { state: "idle", activePeers: 0 } } }))
  await page.route("**/admin/api/settings/cors", route => route.fulfill({ json: { requiredOrigin: "https://match.example", origins: ["https://match.example"] } }))
  await page.route("**/admin/api/pairings", route => route.fulfill({ json: { pairings: saved ? [] : [{ id: "pending-1", comparisonCode: "123456", controller: { displayName: "Owner" }, controllerFingerprint: "owner", serviceFingerprint: "keeper", scopes: [{ title: "Garden", mode: "replicate" }], futureBoards: false, operatorApproved: null, controllerApproved: true }] } }))
  await page.route("**/admin/api/pairings/pending-1/decision", route => {
    attempts++
    if (attempts === 1) return route.fulfill({ status: 503, json: { message: "Decision unavailable" } })
    saved = true
    return route.fulfill({ json: { decision: "approve" } })
  })
  await page.goto("/admin/approvals")
  const approve = page.getByRole("button", { name: "Approve exact boards" })
  await expect(approve).toBeEnabled()
  await approve.click()
  await expect(page.getByRole("alert")).toContainText("Decision unavailable")
  await expect(approve).toBeEnabled()
  await approve.click()
  await expect(page.getByText("No pending keeper requests", { exact: false })).toBeVisible()
  expect(attempts).toBe(2)
})

test("Given an unsubscribe confirmation, when Escape cancels, then dialog closes without request and focus returns", async ({ page }) => {
  await signedIn(page)
  await page.goto("/admin/keepers/keeper-person")
  const unsubscribe = page.getByRole("button", { name: "Unsubscribe", exact: true })
  await unsubscribe.click()
  const dialog = page.getByRole("dialog", { name: "Unsubscribe board" })
  await expect(dialog).toBeVisible()
  await expect(dialog.getByRole("button", { name: "Confirm unsubscribe" })).toBeFocused()
  await page.keyboard.press("Escape")
  await expect(dialog).toBeHidden()
  await expect(unsubscribe).toBeFocused()
})

test("Given a reset confirmation, when Escape cancels, then token stays unsubmitted and focus returns", async ({ page }) => {
  await signedIn(page)
  await page.goto("/admin/settings")
  const reset = page.getByRole("button", { name: "Reset keeper", exact: true })
  await reset.click()
  const dialog = page.getByRole("dialog", { name: "Reset keeper" })
  await expect(dialog).toBeVisible()
  await page.getByLabel("Reset operator token").fill("never-submitted")
  await page.keyboard.press("Escape")
  await expect(dialog).toBeHidden()
  await expect(reset).toBeFocused()
})

test("Given a narrow viewport, when keeper navigation loads, then content fits at 320 pixels", async ({ page }) => {
  await signedIn(page)
  await page.setViewportSize({ width: 320, height: 740 })
  await page.goto("/admin/keepers")
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
})

test("Given operator and Tincanban sessions, when identity exchange completes, then operator approval remains available and logout is scoped", async ({ page }) => {
  const observed: Array<{ url: string; cookie: string; method: string }> = []
  let operatorLoggedOut = false
  await page.route("**/admin/api/session", async route => {
    const request = route.request()
    const cookie = request.headers()["cookie"] ?? ""
    observed.push({ url: request.url(), cookie, method: request.method() })
    if (request.method() === "POST") {
      return route.fulfill({ json: { csrfToken: "operator-csrf", personId: null, displayName: "Operator", operator: true },
        headers: { "Set-Cookie": "mesh_lighthouse_admin=operator-session; HttpOnly; Path=/admin/api; SameSite=Strict" } })
    }
    if (!operatorLoggedOut && cookie.includes("mesh_lighthouse_admin=operator-session")) {
      return route.fulfill({ json: { csrfToken: "operator-csrf", personId: null, displayName: "Operator", operator: true } })
    }
    if (cookie.includes("mesh_lighthouse_identity=owner-session")) {
      return route.fulfill({ json: { csrfToken: "owner-csrf", personId: "owner-person", displayName: "Owner", operator: false } })
    }
    return route.fulfill({ status: 403, json: { message: "Sign in required" } })
  })
  await page.route("**/admin/api/login/exchange", route => route.fulfill({ json: { csrfToken: "owner-csrf", personId: "owner-person", displayName: "Owner", operator: false },
    headers: { "Set-Cookie": "mesh_lighthouse_identity=owner-session; HttpOnly; Path=/admin/api; SameSite=Strict" } }))
  await page.route("**/admin/api/logout*", async route => {
    operatorLoggedOut = true
    return route.fulfill({ status: 204, headers: { "Set-Cookie": "mesh_lighthouse_admin=; HttpOnly; Path=/admin/api; SameSite=Strict; Max-Age=0" } })
  })
  await page.route("**/admin/api/overview", route => route.fulfill({ json: { keeper: { displayName: "Rusty", personId: "keeper-person", deviceId: "device-1", boards: [] }, triggers: [], replication: { state: "idle", activePeers: 0 } } }))
  await page.route("**/admin/api/pairings", route => route.fulfill({ json: { pairings: [{ id: "pending-1", comparisonCode: "123456", controller: { displayName: "Owner" }, controllerFingerprint: "owner", serviceFingerprint: "keeper", scopes: [{ title: "Garden", mode: "replicate" }], futureBoards: false, operatorApproved: null, controllerApproved: true }] } }))
  await page.route("**/admin/api/settings/cors", route => route.fulfill({ json: { requiredOrigin: "https://match.example", origins: ["https://match.example"] } }))
  await page.route("**/admin/api/pairings/pending-1/decision", route => {
    const cookie = route.request().headers()["cookie"] ?? ""
    return cookie.includes("mesh_lighthouse_admin=operator-session")
      ? route.fulfill({ json: { status: { status: "pending" } } })
      : route.fulfill({ status: 403, json: { message: "Operator access required" } })
  })
  await page.goto("/admin/approvals")
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible()
  await page.getByText("Service administration").click()
  await page.locator("#operator-token").fill("operator-token")
  await page.getByRole("button", { name: "Sign in as operator" }).click()
  await expect(page.getByRole("button", { name: "Approve exact boards" })).toBeVisible()
  await page.evaluate(() => { window.history.replaceState(null, "", "/admin/approvals#login=identity-code") })
  await page.reload()
  await expect(page.getByRole("button", { name: "Approve exact boards" })).toBeVisible()
  await page.getByRole("button", { name: "Approve exact boards" }).click()
  await expect.poll(() => observed.at(-1)?.cookie ?? "").toContain("mesh_lighthouse_identity=owner-session")
  await expect.poll(() => observed.at(-1)?.cookie ?? "").toContain("mesh_lighthouse_admin=operator-session")
  await page.getByRole("button", { name: "Sign out" }).click()
  await page.reload()
  await expect(page.getByRole("button", { name: "Approve exact boards" })).toHaveCount(0)
  await expect.poll(() => observed.at(-1)?.cookie ?? "").toContain("mesh_lighthouse_identity=owner-session")
  await expect.poll(() => observed.at(-1)?.cookie ?? "").not.toContain("mesh_lighthouse_admin=operator-session")
})
