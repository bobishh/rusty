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
