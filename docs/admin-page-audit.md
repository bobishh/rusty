# Rusty admin pages and API coverage

Rusty admin API supports reading one authenticated keeper overview, reviewing pairing requests, updating operator CORS origins, unsubscribing boards, and resetting keeper data. It does not expose keeper create, edit, or delete endpoints. UI therefore lists the authenticated keeper and sends new connections through Match → Sync → Add keeper.

| Page | Route | Supported operations |
| --- | --- | --- |
| Keepers index | `/admin/` or `/admin/keepers` | Show authenticated keeper, board count and names; open keeper detail |
| Keeper detail | `/admin/keepers/:personId` | Read boards and triggers; unsubscribe a board with confirmation |
| Approvals | `/admin/approvals` | Review pending pairings; operator approve or decline |
| Settings | `/admin/settings` | Operator edit allowed CORS origins; reset keeper with token confirmation |

Navigation supports direct routes, browser back/forward and reload. Owner sessions do not receive the operator Settings link and are redirected from that route. Native confirmation dialogs retain focus behavior and block dismissal while a request is pending. API failures stay visible and allow retry.

| Endpoint | Method | Page/action |
| --- | --- | --- |
| `/admin/api/overview` | GET | Authenticated keeper, boards and triggers |
| `/admin/api/pairings` | GET | Pending approval list |
| `/admin/api/pairings/:id/decision` | POST | Operator approve or decline |
| `/admin/api/settings/cors` | GET, POST | Operator origin settings |
| `/admin/api/boards/:id/unsubscribe` | POST | Disconnect board |
| `/admin/api/reset` | POST | Operator reset token confirmation |

No keeper create, edit, or delete endpoint exists. Adding those controls would claim operations the service cannot perform.
