'use strict'

/**
 * Instrumentación Prometheus para latencia P95 y disponibilidad.
 *
 * Métricas expuestas:
 *   - http_request_duration_ms  (Histogram) → calcula P50/P95/P99
 *   - http_active_requests      (Gauge)     → presión instantánea
 *   - circuit_breaker_state     (Gauge)     → 0=CLOSED, 1=HALF_OPEN, 2=OPEN
 *   - rate_limit_exceeded_total (Counter)   → requests bloqueados
 *   - Métricas default de Node.js: CPU, memoria, event loop lag
 */

const client = require('prom-client')

const register = new client.Registry()

// Recolectar métricas por defecto de Node.js (event loop lag, GC, etc.)
client.collectDefaultMetrics({
  register,
  gcDurationBuckets: [0.001, 0.01, 0.1, 1, 2, 5]
})

// ── Histograma de duración de requests ──────────────────────────────
const httpDuration = new client.Histogram({
  name: 'http_request_duration_ms',
  help: 'Duración de requests HTTP en milisegundos',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000],
  registers: [register]
})

// ── Gauge de requests activos ────────────────────────────────────────
const activeRequests = new client.Gauge({
  name: 'http_active_requests',
  help: 'Número de requests HTTP activos en este momento',
  registers: [register]
})

// ── Estado del Circuit Breaker ───────────────────────────────────────
const circuitBreakerState = new client.Gauge({
  name: 'circuit_breaker_state',
  help: 'Estado del circuit breaker: 0=CLOSED, 1=HALF_OPEN, 2=OPEN',
  labelNames: ['name'],
  registers: [register]
})

// ── Contador de rate limit hits ──────────────────────────────────────
const rateLimitHits = new client.Counter({
  name: 'rate_limit_exceeded_total',
  help: 'Total de requests rechazados por rate limiting',
  labelNames: ['endpoint'],
  registers: [register]
})

/**
 * Normaliza el path del request para evitar cardinalidad explosiva
 * en las métricas (evita que cada UUID o ID sea un label distinto).
 */
function normalizePath (req) {
  if (req.route && req.route.path) return req.route.path

  // Reemplazar segmentos numéricos y UUIDs por parámetro genérico
  return req.path
    .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '/:uuid')
    .replace(/\/\d+/g, '/:id')
}

/**
 * Middleware Express que instrumenta cada request HTTP.
 * Se debe montar ANTES de las rutas.
 */
function metricsMiddleware (req, res, next) {
  // No instrumentar el propio endpoint de métricas
  if (req.path === '/metrics') return next()

  const end = httpDuration.startTimer()
  activeRequests.inc()

  res.on('finish', () => {
    activeRequests.dec()
    const route = normalizePath(req)
    end({ method: req.method, route, status_code: res.statusCode })
  })

  next()
}

module.exports = {
  register,
  metricsMiddleware,
  circuitBreakerState,
  rateLimitHits
}
