import test from "node:test"
import assert from "node:assert/strict"
import { readStatusReply, statusMessageMatches } from "../src/ui/storage-status.mjs"

const now = 1_000_000
const source = {}
const request = { origin: "https://rusty.example", frontendOrigin: "https://board.example", requestId: "a".repeat(32), expiresAt: now + 120_000, source }
const reply = { type: "rusty-status@1", requestId: request.requestId, origin: request.origin, checkedAt: now,
  boards: [{ id: "board-one", title: "<img onerror=alert(1)>", status: "Access required", access: "read-only" }] }

test("Given another source, origin, nonce or expired request, when a message arrives, then ignore it", () => {
  const event = { source, origin: request.frontendOrigin, data: reply }
  assert.equal(statusMessageMatches(event, request, now), true)
  for (const changed of [{ source: {} }, { origin: "https://other.example" }, { data: { ...reply, requestId: "wrong" } }]) {
    assert.equal(statusMessageMatches({ ...event, ...changed }, request, now), false)
  }
  assert.equal(statusMessageMatches(event, request, request.expiresAt), false)
})

test("Given a matching status snapshot, when decoding it, then retain plain bounded fields without credentials", () => {
  const value = readStatusReply({ ...reply, readToken: "secret", boards: [{ ...reply.boards[0], contentKey: "secret" }] }, request, now)
  assert.deepEqual(value, { checkedAt: now, boards: reply.boards })
  assert.equal(JSON.stringify(value).includes("secret"), false)
  for (const boards of [Array(129).fill(reply.boards[0]), [{ ...reply.boards[0], id: "../private" }], [{ ...reply.boards[0], title: "x".repeat(513) }], [{ ...reply.boards[0], status: "invented success" }]]) {
    assert.throws(() => readStatusReply({ ...reply, boards }, request, now))
  }
  assert.throws(() => readStatusReply({ ...reply, checkedAt: now + 10_000 }, request, now))
})
