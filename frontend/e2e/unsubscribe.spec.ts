import { expect, test } from "@playwright/test"

for (const fails of [false, true]) {
  test(`Given an attached board, when operator unsubscribes, then ${fails ? "failure preserves board and allows retry" : "board disappears after confirmation"}`, async ({ page }) => {
    let attached = true
    let attempts = 0
    await page.route("**/admin/api/session", route => route.fulfill({ json: { csrfToken: "csrf", personId: null, displayName: "Operator", operator: true } }))
    await page.route("**/admin/api/settings/cors", route => route.fulfill({ json: { requiredOrigin: "https://match.example", origins: ["https://match.example"] } }))
    await page.route("**/admin/api/pairings", route => route.fulfill({ json: { pairings: [] } }))
    await page.route("**/admin/api/overview", route => route.fulfill({ json: {
      keeper: { displayName: "Lighthouse", personId: "keeper", deviceId: "device", boards: attached ? [{ workspaceId: "old-board", title: "Old Job search", isPrimary: true, heads: [], peerCount: 1 }] : [] },
      triggers: [], replication: { state: "idle", activePeers: 0 },
    } }))
    await page.route("**/admin/api/boards/old-board/unsubscribe", route => {
      expect(route.request().headers()["x-csrf-token"]).toBe("csrf")
      attempts++
      if (fails && attempts === 1) return route.fulfill({ status: 503, json: { message: "Could not detach board" } })
      attached = false
      return route.fulfill({ json: { detached: true } })
    })
    await page.goto("/admin/")
    await page.getByRole("button", { name: "Unsubscribe", exact: true }).click()
    await expect(page.getByText("Stop replicating Old Job search?", { exact: true })).toBeVisible()
    expect(attempts).toBe(0)
    await page.getByRole("button", { name: "Confirm unsubscribe", exact: true }).click()
    if (fails) {
      await expect(page.getByRole("alert")).toContainText("Could not detach board")
      await expect(page.getByText("Old Job search", { exact: true })).toBeVisible()
      await page.getByRole("button", { name: "Confirm unsubscribe", exact: true }).click()
    }
    await expect(page.getByText("No attached boards.")).toBeVisible()
    await page.reload()
    await expect(page.getByText("No attached boards.")).toBeVisible()
  })
}

test("Given failed board setup, when operator opens Lighthouse, then exact join error is visible", async ({ page }) => {
  await page.route("**/admin/api/session", route => route.fulfill({ json: { csrfToken: "csrf", personId: null, displayName: "Operator", operator: true } }))
  await page.route("**/admin/api/settings/cors", route => route.fulfill({ json: { requiredOrigin: "https://match.example", origins: ["https://match.example"] } }))
  await page.route("**/admin/api/overview", route => route.fulfill({ json: { keeper: { displayName: "Lighthouse", personId: "keeper", deviceId: "device", boards: [] }, triggers: [], replication: { state: "idle", activePeers: 0 } } }))
  await page.route("**/admin/api/pairings", route => route.fulfill({ json: { pairings: [{ id: "failed", comparisonCode: "123456", controller: { displayName: "Owner" }, controllerFingerprint: "owner", serviceFingerprint: "keeper", scopes: [{ title: "Restored board", mode: "read" }], futureBoards: false, operatorApproved: true, controllerApproved: true, provisioning: { status: "provisioning", scopes: [{ workspaceId: "restored", status: "pending", error: "join_failed", errorDetail: "Mesh snapshot rejected: stale authorization epoch" }] } }] } }))
  await page.goto("/admin/")
  await expect(page.getByRole("alert")).toHaveText("restored: Mesh snapshot rejected: stale authorization epoch")
  await expect(page.getByText("Board setup: provisioning", { exact: true })).toBeVisible()
})

test("Given ambiguous JEV board target, when operator opens boards, then unsubscribe remains available beside exact intake error", async ({ page }) => {
  await page.route("**/admin/api/session", route => route.fulfill({ json: { csrfToken: "csrf", personId: null, displayName: "Operator", operator: true } }))
  await page.route("**/admin/api/settings/cors", route => route.fulfill({ json: { requiredOrigin: "https://match.example", origins: ["https://match.example"] } }))
  await page.route("**/admin/api/pairings", route => route.fulfill({ json: { pairings: [] } }))
  await page.route("**/admin/api/overview", route => route.fulfill({ json: { keeper: { displayName: "Lighthouse", personId: "keeper", deviceId: "device", boards: [{ workspaceId: "jobs", title: "Job search", isPrimary: true, heads: [], peerCount: 1 }] }, triggers: [{ id: "jev", name: "JEV intake", configured: true, pendingCount: 0, model: "test", errorDetail: "Multiple job-search boards in keeper scopes", outcomes: { cardCreated: 0, chatQueued: 0, awaitingMesh: 1 } }], replication: { state: "idle", activePeers: 0 } } }))
  await page.goto("/admin/")
  await expect(page.getByRole("alert")).toHaveText("Multiple job-search boards in keeper scopes")
  await expect(page.getByRole("button", { name: "Unsubscribe", exact: true })).toBeVisible()
})
