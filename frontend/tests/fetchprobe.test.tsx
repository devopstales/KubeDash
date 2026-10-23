import { expect, test } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from './msw'
import { apiFetch } from '../src/lib/api'
import { useClusterStore } from '../src/store/cluster'
import type { ClusterEvent, MetricsSummary } from '../src/lib/types'

// ponytail: jsdom has no layout — rendering the view pulls in CChart's
// canvas/ResizeObserver (no jsdom stubs outside the donut's own test), which
// throws unhandled. Assert the fetch seam instead: apiFetch builds absolute
// URLs from VITE_API_BASE (pinned in vite.config.ts), so a wildcard MSW
// handler on the pinned origin is only reachable when the base is set.
test('dashboard fetch seam reaches MSW through the pinned VITE_API_BASE', async () => {
  useClusterStore.setState({ selectedCluster: { id: 1, name: 'prod' } })
  server.use(
    http.get('*/api/v1/clusters/1/metrics/summary', () =>
      HttpResponse.json({
        cluster: 'prod',
        metrics_available: true,
        cpu: {
          capacity_millicores: 100,
          used_millicores: 50,
          requests_millicores: 20,
          limits_millicores: 0,
        },
        memory: {
          capacity_bytes: 100,
          used_bytes: 50,
          requests_bytes: 20,
          limits_bytes: 0,
        },
        pods: { capacity: 10, running: 1, pending: 0, completed: 0 },
      }),
    ),
    http.get('*/api/v1/clusters/1/events', () => HttpResponse.json([])),
  )
  const [summary, events] = await Promise.all([
    apiFetch<MetricsSummary>('/api/v1/clusters/1/metrics/summary'),
    apiFetch<ClusterEvent[]>('/api/v1/clusters/1/events'),
  ])
  expect(summary.error).toBeNull()
  expect(summary.data?.cpu.used_millicores).toBe(50)
  expect(events.error).toBeNull()
  expect(events.data).toEqual([])
})
