import { expect, test } from "@playwright/test"

for (const unavailable of [false, true]) {
  test(`Given Rusty ${unavailable ? "session outage" : "sign-in"}, when opening its real admin route, then paired branding and usable controls stay visible`, async ({ page }) => {
    await page.route("**/admin/api/session", route => route.fulfill({ status: unavailable ? 503 : 403, json: { message: unavailable ? "Unavailable" : "Forbidden" } }))
    await page.goto("/admin/")
    await expect(page).toHaveTitle("Rusty · Keeper")
    await expect(page.getByRole("heading", { name: "RUSTY", exact: true })).toBeVisible()
    const robot = page.getByRole("img", { name: "Rusty", exact: true })
    await expect(robot).toBeVisible()
    expect(await page.locator("main").evaluate(el => getComputedStyle(el).fontFamily)).toContain("Fira Code")
    expect(await page.getByRole("heading", { name: "RUSTY", exact: true }).evaluate(el => getComputedStyle(el).fontFamily)).toContain("Caveat")
    expect(await page.locator("main h2").evaluate(el => getComputedStyle(el).fontFamily)).toContain("Fira Code")
    expect(await robot.evaluate(image => ({ width: image.getBoundingClientRect().width, height: image.getBoundingClientRect().height }))).toEqual({ width: 32, height: 40 })
    await expect(page.getByRole("button", { name: unavailable ? "Retry session check" : "Sign in with Match", exact: true })).toBeVisible()
    const controls = await page.locator("main .button, .login-card").evaluateAll(elements => elements.map(el => ({ radius: getComputedStyle(el).borderRadius, border: getComputedStyle(el).borderTopWidth })))
    expect(controls.every(control => control.radius === "0px" && control.border === "2px")).toBe(true)
    const favicon = await page.locator('link[rel="icon"]').getAttribute("href")
    expect(favicon).toContain("rusty-head")
    const response = await page.request.get(favicon!)
    expect(response.ok()).toBe(true)
    await page.evaluate(() => document.fonts.load('20px "Caveat"'))
    expect(await page.evaluate(() => document.fonts.check('20px "Caveat"'))).toBe(true)
    expect(await page.evaluate(() => getComputedStyle(document.documentElement).fontSize)).toBe("20px")
    await page.screenshot({ path: unavailable ? "/tmp/rusty-pending.png" : "/tmp/rusty-desktop.png" })
  })
}

test("Given narrow viewport, when Rusty opens, then robot and header fit without overflow", async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 812 })
  await page.route("**/admin/api/session", route => route.fulfill({ status: 403, json: { message: "Forbidden" } }))
  await page.goto("/admin/")
  await expect(page.getByRole("img", { name: "Rusty", exact: true })).toBeVisible()
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await page.evaluate(() => document.fonts.load('20px "Caveat"'))
  await page.screenshot({ path: "/tmp/rusty-mobile.png" })
})
