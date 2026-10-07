import { expect, test } from "@playwright/test"

test("Given approved board setup, when its live status becomes active, then it leaves pending approvals while its board remains", async ({ page }) => {
  await page.clock.install()
  let active = false
  let fail = false
  const pairing = () => ({ id: "joined", comparisonCode: "603886", controller: { displayName: "Valiant Squirrel" }, controllerFingerprint: "owner", serviceFingerprint: "keeper", scopes: [{ title: "Job search", mode: "replicate" }], futureBoards: true, operatorApproved: true, controllerApproved: true, provisioning: { status: active ? "active" : "provisioning", scopes: [{ workspaceId: "jobs", status: active ? "active" : "pending" }] } })
  await page.route("**/admin/api/session", route => route.fulfill({ json: { csrfToken: "csrf", personId: null, displayName: "Operator", operator: true } }))
  await page.route("**/admin/api/overview", route => route.fulfill({ json: { keeper: { displayName: "Keeper", personId: "keeper", deviceId: "device", boards: [{ workspaceId: "jobs", title: "Job search", isPrimary: true, heads: [], peerCount: 1, replication: { state: "connected", activePeers: 1 } }] }, triggers: [], replication: { state: "connected", activePeers: 1 } } }))
  await page.route("**/admin/api/settings/cors", route => route.fulfill({ json: { requiredOrigin: "https://match.example", origins: ["https://match.example"] } }))
  await page.route("**/admin/api/pairings", route => fail ? route.fulfill({ status: 503, json: { message: "Status temporarily unavailable" } }) : route.fulfill({ json: { pairings: [pairing()] } }))
  await page.goto("/admin/approvals")
  await expect(page.getByRole("heading", { name: "Approvals (1)", exact: true })).toBeVisible()
  await expect(page.getByText("Board setup: provisioning", { exact: true })).toBeVisible()
  fail = true
  active = true
  await page.clock.runFor(5000)
  await expect(page.getByRole("status")).toContainText("Status temporarily unavailable")
  await expect(page.getByRole("heading", { name: "Approvals (1)", exact: true })).toBeVisible()
  fail = false
  await page.clock.runFor(5000)
  await expect(page.getByRole("heading", { name: "Approvals", exact: true })).toBeVisible()
  await expect(page.getByText("No pending keeper requests", { exact: false })).toBeVisible()
  await expect(page.locator(".approval-card")).toHaveCount(0)
  await page.goto("/admin/keepers/keeper")
  await expect(page.getByText("Job search", { exact: true })).toBeVisible()
  await expect(page.getByRole("status")).toHaveCount(0)
})
