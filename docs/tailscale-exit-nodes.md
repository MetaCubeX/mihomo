# Tailscale exit-node discovery

`GET /proxies/{name}/tailscale/exit-nodes` reads the exit-node candidates visible
to the named, concrete Tailscale outbound. URL-encode the outbound name. This
endpoint uses the existing external-controller authentication, just like the
other `/proxies` endpoints. Proxy groups are not followed.

No system Tailscale client, additional login, or tailnet API key is needed. The
request uses only that outbound's embedded tsnet LocalClient. It does not expose
LocalAPI, authentication URLs, keys, user profiles, or other status fields, and
does not modify preferences or select an exit node.

Example response:

```json
{
  "state": "Ready",
  "backendState": "Running",
  "exitNodes": [
    {
      "id": "nExample",
      "hostName": "gateway",
      "dnsName": "gateway.example.ts.net.",
      "tailscaleIPs": ["100.64.0.10"],
      "online": true,
      "exitNodeOption": true,
      "exitNode": false
    }
  ]
}
```

`id` is the Tailscale stable node ID, suitable for tracking a candidate across
refreshes; it is not a new supported value for the outbound's `exit-node` config
option. Use a returned Tailscale IP or name with that existing option.
`exitNode` indicates the currently selected exit node. `exitNodeOption` is true
for every returned candidate: Tailscale considers its exit routes both offered
and approved. Merely advertising routes is insufficient. Expired nodes and
peers absent from the current network map are excluded. Approved offline nodes
are included with `online: false`; neither approval nor online presence proves
end-to-end connectivity. Results are sorted by stable ID.

The request is observational and does **not** lazily start an unused outbound.
Starting tsnet can create state, initiate login, and open network connections;
those side effects remain with existing outbound usage. Callers should inspect
`state` before treating an empty `exitNodes` array as an authoritative result:

| State | Meaning |
| --- | --- |
| `NotStarted` | This outbound has not been started by traffic or DNS use. |
| `Starting`, `NoState` | tsnet or its backend is initializing. |
| `NeedsLogin` | The instance requires authentication. |
| `NeedsMachineAuth` | The device requires administrator approval. |
| `Stopped` | The backend is stopped. |
| `Synchronizing` | The backend is running but has no self node in its network map yet. |
| `Disconnected` | A network map exists, but the instance has no live streamed control connection; cached candidates are withheld. |
| `Ready` | The backend is running, has a self node in its network map, and reports a live control connection. An empty array means no eligible candidates are currently visible. |
| `Closed` | The outbound was closed, for example during configuration replacement. |

Other backend states are passed through in `state`. `backendState` is omitted
before a backend status is available. Discovery is a snapshot of the instance's
current view, not a forced control-plane refresh or a connectivity test.

A missing name returns HTTP 404; a non-Tailscale outbound (including groups)
returns 400. Initialization or LocalAPI query failures return 502 with a generic
message, distinct from a successful empty list. A query has a five-second upper
bound (or the request's earlier deadline), returning 504 on timeout. Request
cancellation and outbound shutdown cancel an in-flight LocalAPI call. A closed
instance cannot publish a newly initialized discovery client.

The optional outbound capability keeps existing proxy interfaces unchanged and
does not import Tailscale into builds that omit `with_gvisor` or use
`no_tailscale`. Such builds still handle the controller path and reject adapters
that do not implement discovery.
