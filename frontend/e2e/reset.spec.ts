import { expect, test } from "@playwright/test"

for (const rejected of [false, true]) {
  test(`Given operator data, when reset token is submitted, then ${rejected ? "wrong token preserves data and retry succeeds" : "reset waits for restart then requires sign-in"}`, async ({ page }) => {
    let restarting = false
    let attempts = 0
    await page.route("**/admin/api/session", route => restarting ? route.fulfill({ status: 403, json: { message: "Forbidden" } }) : route.fulfill({ json: { csrfToken: "csrf", personId: null, displayName: "Operator", operator: true } }))
    await page.route("**/admin/api/settings/cors", route => route.fulfill({ json: { requiredOrigin: "https://match.example", origins: [] } }))
    await page.route("**/admin/api/pairings", route => route.fulfill({ json: { pairings: [] } }))
    await page.route("**/admin/api/overview", route => route.fulfill({ json: { keeper: { displayName: "Lighthouse", personId: "keeper", deviceId: "device", boards: [{ workspaceId: "old", title: "Old board", isPrimary: true, heads: [], peerCount: 1 }] }, triggers: [], replication: { state: "idle", activePeers: 0 } } }))
    await page.route("**/admin/api/reset", route => {
      attempts++
      expect(route.request().headers()["x-csrf-token"]).toBe("csrf")
      expect(route.request().postDataJSON().secret).toBe(rejected && attempts === 1 ? "wrong-token" : "operator-token")
      if (rejected && attempts === 1) return route.fulfill({ status: 403, json: { message: "Invalid operator token" } })
      restarting = true
      return route.fulfill({ status: 202, json: { resetting: true } })
    })
    await page.goto("/admin/settings")
    await page.getByRole("button", { name: "Reset keeper", exact: true }).click()
    expect(attempts).toBe(0)
    await page.getByLabel("Reset operator token", { exact: true }).fill(rejected ? "wrong-token" : "operator-token")
    await page.getByRole("button", { name: "Delete all keeper data", exact: true }).click()
    if (rejected) {
      await expect(page.getByRole("alert")).toContainText("Invalid operator token")
      await expect(page.getByRole("dialog", { name: "Reset keeper" })).toBeVisible()
      expect(attempts).toBe(1)
      await page.getByLabel("Reset operator token", { exact: true }).fill("operator-token")
      await page.getByRole("button", { name: "Delete all keeper data", exact: true }).click()
    }
    await expect(page.getByRole("status")).toContainText("Reset requested")
    await expect(page.getByText("Keeper reset. Sign in again to add boards.", { exact: true })).toBeVisible({ timeout: 10_000 })
    await expect(page.getByText("Old board", { exact: true })).toHaveCount(0)
  })
}

test("Given owner session, when settings opens, then reset control is absent", async ({ page }) => {
  await page.route("**/admin/api/session", route => route.fulfill({ json: { csrfToken: "csrf", personId: "owner", displayName: "Owner", operator: false } }))
  await page.route("**/admin/api/pairings", route => route.fulfill({ json: { pairings: [] } }))
  await page.route("**/admin/api/overview", route => route.fulfill({ json: { keeper: { displayName: "Lighthouse", personId: "keeper", deviceId: "device", boards: [] }, triggers: [], replication: { state: "idle", activePeers: 0 } } }))
  await page.goto("/admin/")
  await expect(page.getByRole("heading", { name: "Keepers", exact: true })).toBeVisible()
  await expect(page.getByRole("button", { name: "Reset keeper", exact: true })).toHaveCount(0)
})

test("Given broken overview, when operator signs in, then reset is still available", async ({ page }) => {
  await page.route("**/admin/api/session", route => route.fulfill({ json: { csrfToken: "csrf", personId: null, displayName: "Operator", operator: true } }))
  await page.route("**/admin/api/pairings", route => route.fulfill({ json: { pairings: [] } }))
  await page.route("**/admin/api/settings/cors", route => route.fulfill({ json: { requiredOrigin: "https://match.example", origins: [] } }))
  await page.route("**/admin/api/overview", route => route.fulfill({ status: 503, json: { message: "Overview unavailable" } }))
  await page.goto("/admin/settings")
  await expect(page.getByRole("status")).toContainText("Overview unavailable")
  await expect(page.getByRole("button", { name: "Reset keeper", exact: true })).toBeVisible()
})
