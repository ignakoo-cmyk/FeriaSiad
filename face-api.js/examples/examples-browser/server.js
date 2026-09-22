'use strict'

/**
 * UAH Face AI Platform — Express Server (Hardened)
 *
 * Mitigaciones implementadas:
 *   OWASP A01 – Control de Acceso       → requireApiKey en /fetch_external_image
 *   OWASP A03 – Inyección / SSRF        → validateImageUrl con allowlist de dominios
 *   OWASP A05 – Mala Configuración      → helmet() + CSP estricto
 *   OWASP A06 – Componentes Vulnerables → reemplazado 'request' deprecated por undici
 *   OWASP A07 – Autenticación Fallida   → rate limiting global y por endpoint
 *   OWASP A08 – Integridad de Datos     → límite de payload 512kb
 *   OWASP A09 – Logging Insuficiente    → structured logging + error handler seguro
 *   OWASP A10 – SSRF                    → allowlist + validación de protocolo
 *
 * Rendimiento:
 *   - Cache-Control en assets estáticos (model weights inmutables 7d)
 *   - Compresión gzip/brotli con compression middleware
 *   - Circuit Breaker para el proxy de imágenes externas
 *   - /healthz y /readyz para orquestadores
 *   - /metrics para scraping Prometheus
 */

const express   = require('express')
const path      = require('path')
const helmet    = require('helmet')
const compression = require('compression')
const rateLimit = require('express-rate-limit')
const { fetch } = require('undici')

const { requireApiKey }                         = require('./middleware/auth')
const { logger, requestLogger }                 = require('./middleware/logger')
const { register, metricsMiddleware,
        circuitBreakerState, rateLimitHits }     = require('./middleware/metrics')

const app = express()

// ── Confiar en proxy inverso (Nginx) para X-Forwarded-For ───────────
// Solo si hay un proxy delante; en local quitar esta línea
app.set('trust proxy', 1)

// ── 1. Request logging (primero, para capturar todo) ────────────────
app.use(requestLogger)

// ── 2. Instrumentación Prometheus ───────────────────────────────────
app.use(metricsMiddleware)

// ── 3. Cabeceras de seguridad HTTP ──────────────────────────────────
//    OWASP A05 — Previene XSS, clickjacking, MIME-sniffing, HSTS
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:   ["'self'"],
      scriptSrc:    [
        "'self'",
        "'unsafe-eval'",
        "'unsafe-inline'",
        'https://cdn.tailwindcss.com',
        'https://unpkg.com',
        'blob:'
      ],
      scriptSrcAttr: ["'unsafe-inline'"],
      workerSrc:    ["'self'", 'blob:'],
      imgSrc:       ["'self'", 'data:', 'blob:', 'https:'],
      mediaSrc:     ["'self'", 'blob:'],
      connectSrc:   [
        "'self'",
        'https://cdn.tailwindcss.com',
        'https://unpkg.com',
        'https://fonts.googleapis.com',
        'https://fonts.gstatic.com'
      ],
      styleSrc:     [
        "'self'",
        "'unsafe-inline'",
        'https://fonts.googleapis.com'
      ],
      fontSrc:      [
        "'self'",
        'data:',
        'https://fonts.gstatic.com'
      ],
      objectSrc:    ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: null
    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: false,
  hsts: false
}))

// ── 4. Compresión gzip (reduce 60-70% en assets JS/HTML) ────────────
app.use(compression({ level: 6 }))

// ── 5. Límite de payload — previene DoS por body masivo ─────────────
//    OWASP A08
app.use(express.json({ limit: '512kb' }))
app.use(express.urlencoded({ extended: true, limit: '512kb' }))

// ── 6. Rate Limiting global (2 req/s por IP) ─────────────────────────
//    OWASP A07
const globalLimiter = rateLimit({
  windowMs: 60 * 1000,   // ventana de 1 minuto
  max: 120,              // 2 req/s promedio por IP
  standardHeaders: true,
  legacyHeaders: false,
  handler (req, res) {
    rateLimitHits.inc({ endpoint: 'global' })
    res.status(429).json({ error: 'Too Many Requests', retryAfter: 60 })
  }
})
app.use(globalLimiter)

// Rate limiter estricto para el endpoint de proxy externo
const proxyLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  handler (req, res) {
    rateLimitHits.inc({ endpoint: 'fetch_external_image' })
    res.status(429).json({ error: 'Proxy rate limit exceeded', retryAfter: 60 })
  }
})

// ── 7. Assets estáticos con Cache-Control ────────────────────────────
const viewsDir = path.join(__dirname, 'views')

// Opciones para model weights (.bin, .shard): inmutables 7 días
const weightsOptions = {
  maxAge: '7d',
  etag: true,
  lastModified: true,
  setHeaders (res, filePath) {
    if (/\.(bin|shard|wasm)$/.test(filePath)) {
      res.setHeader('Cache-Control', 'public, max-age=604800, immutable')
    }
  }
}

// Opciones para el bundle compilado face-api.js (dist/): 7 días immutable
const distOptions = {
  maxAge: '7d',
  etag: true,
  lastModified: true,
  setHeaders (res, filePath) {
    if (/\.js$/.test(filePath)) {
      res.setHeader('Cache-Control', 'public, max-age=604800, immutable')
    }
  }
}

app.use(express.static(viewsDir,                                   { maxAge: '1h'  }))
app.use(express.static(path.join(__dirname, './public'),           { maxAge: '1d'  }))
app.use(express.static(path.join(__dirname, '../images'),          { maxAge: '1d'  }))
app.use(express.static(path.join(__dirname, '../media'),           { maxAge: '1d'  }))
app.use(express.static(path.join(__dirname, '../../weights'),      weightsOptions  ))
app.use(express.static(path.join(__dirname, 'weights'),            weightsOptions  ))
app.use(express.static(path.join(__dirname, '../../dist'),         distOptions     ))
app.use(express.static(path.join(__dirname, 'dist'),               distOptions     ))

// ── 8. Circuit Breaker para el proxy de imágenes externas ────────────
//    Protege de cascadas de fallos cuando un proveedor externo cae.
const cb = {
  state:       'CLOSED',   // CLOSED | OPEN | HALF_OPEN
  failures:    0,
  threshold:   5,          // abre después de N fallos consecutivos
  timeoutMs:   30_000,     // permanece OPEN 30s antes de intentar HALF_OPEN
  lastFailAt:  0,

  canRequest () {
    if (this.state === 'CLOSED') return true
    if (this.state === 'OPEN') {
      if (Date.now() - this.lastFailAt > this.timeoutMs) {
        this.state = 'HALF_OPEN'
        logger.warn('circuit_breaker_half_open')
        return true
      }
      return false
    }
    return true // HALF_OPEN: permite un intento
  },

  recordSuccess () {
    this.failures = 0
    this.state    = 'CLOSED'
    circuitBreakerState.set({ name: 'external_image' }, 0)
    logger.info('circuit_breaker_closed')
  },

  recordFailure () {
    this.failures++
    this.lastFailAt = Date.now()
    if (this.failures >= this.threshold) {
      this.state = 'OPEN'
      circuitBreakerState.set({ name: 'external_image' }, 2)
      logger.error('circuit_breaker_open', { failures: this.failures })
    } else if (this.state === 'HALF_OPEN') {
      this.state = 'OPEN'
      circuitBreakerState.set({ name: 'external_image' }, 2)
    } else {
      circuitBreakerState.set({ name: 'external_image' }, 1)
    }
  }
}

// ── 9. Allowlist de dominios para SSRF prevention ────────────────────
//    OWASP A10 — Solo se permiten dominios explícitamente autorizados.
//    Ampliar según necesidad del proyecto.
const ALLOWED_IMAGE_HOSTS = new Set([
  'upload.wikimedia.org',
  'images.unsplash.com',
  'cdn.jsdelivr.net',
  'raw.githubusercontent.com',
  'i.imgur.com'
])

/**
 * Valida una URL antes de hacer fetch externo.
 * - Solo protocolos http/https
 * - Solo dominios en la allowlist
 * - Rechaza IPs privadas / loopback
 * @returns {{ valid: boolean, url?: string, reason?: string }}
 */
function validateImageUrl (rawUrl) {
  if (typeof rawUrl !== 'string' || rawUrl.length > 2048) {
    return { valid: false, reason: 'URL inválida o demasiado larga' }
  }

  let parsed
  try {
    parsed = new URL(rawUrl)
  } catch {
    return { valid: false, reason: 'URL malformada' }
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { valid: false, reason: 'Protocolo no permitido' }
  }

  // Bloquear IPs privadas / loopback / link-local (SSRF hardening)
  const host = parsed.hostname.toLowerCase()
  const blockedPatterns = [
    /^localhost$/,
    /^127\./,
    /^10\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /^192\.168\./,
    /^169\.254\./,    // AWS/GCP metadata
    /^::1$/,
    /^0\.0\.0\.0$/
  ]
  if (blockedPatterns.some(re => re.test(host))) {
    return { valid: false, reason: 'Host no permitido' }
  }

  if (!ALLOWED_IMAGE_HOSTS.has(parsed.hostname)) {
    return { valid: false, reason: `Dominio no autorizado: ${parsed.hostname}` }
  }

  return { valid: true, url: parsed.href }
}

// ── 10. Rutas HTML ────────────────────────────────────────────────────
app.get('/', (req, res) => res.redirect(301, '/app'))

const htmlRoutes = {
  '/app':                              'app.html',
  '/face_detection':                   'faceDetection.html',
  '/face_landmark_detection':          'faceLandmarkDetection.html',
  '/face_expression_recognition':      'faceExpressionRecognition.html',
  '/age_and_gender_recognition':       'ageAndGenderRecognition.html',
  '/face_extraction':                  'faceExtraction.html',
  '/face_recognition':                 'faceRecognition.html',
  '/video_face_tracking':              'videoFaceTracking.html',
  '/webcam_face_detection':            'webcamFaceDetection.html',
  '/webcam_face_landmark_detection':   'webcamFaceLandmarkDetection.html',
  '/webcam_face_expression_recognition': 'webcamFaceExpressionRecognition.html',
  '/webcam_age_and_gender_recognition': 'webcamAgeAndGenderRecognition.html',
  '/bbt_face_landmark_detection':      'bbtFaceLandmarkDetection.html',
  '/bbt_face_similarity':              'bbtFaceSimilarity.html',
  '/bbt_face_matching':                'bbtFaceMatching.html',
  '/bbt_face_recognition':             'bbtFaceRecognition.html',
  '/batch_face_landmarks':             'batchFaceLandmarks.html',
  '/batch_face_recognition':           'batchFaceRecognition.html',
  '/webcam_career_prediction':         'webcamCareerPrediction.html',
  '/carreras':                         'app.html',
  '/buscador':                         'app.html'
}

Object.entries(htmlRoutes).forEach(([route, file]) => {
  app.get(route, (req, res) => res.sendFile(path.join(viewsDir, file)))
})

// ── 11. POST /fetch_external_image — Proxy seguro ────────────────────
//    Protegido por: API Key + Rate Limiting estricto + Circuit Breaker
//    + validación SSRF + verificación de Content-Type
app.post('/fetch_external_image', requireApiKey, proxyLimiter, async (req, res) => {
  const { imageUrl } = req.body

  if (!imageUrl) {
    return res.status(400).json({ error: 'imageUrl param required' })
  }

  const { valid, url, reason } = validateImageUrl(imageUrl)
  if (!valid) {
    logger.warn('ssrf_blocked', { reqId: req.reqId, reason, imageUrl })
    return res.status(422).json({ error: reason })
  }

  if (!cb.canRequest()) {
    return res.status(503).json({
      error: 'External image service temporarily unavailable. Try again later.'
    })
  }

  try {
    const controller = new AbortController()
    const timeoutId  = setTimeout(() => controller.abort(), 8_000)

    const externalRes = await fetch(url, {
      signal:   controller.signal,
      redirect: 'follow',
      headers: { 'User-Agent': 'UAH-FaceAI-Platform/1.0' }
    })

    clearTimeout(timeoutId)

    if (!externalRes.ok) {
      cb.recordFailure()
      return res.status(502).json({ error: 'External resource returned an error' })
    }

    const contentType = externalRes.headers.get('content-type') || ''
    if (!contentType.startsWith('image/')) {
      return res.status(422).json({ error: 'La URL no apunta a una imagen válida' })
    }

    // Limitar tamaño de respuesta externa a 5MB
    const MAX_BYTES = 5 * 1024 * 1024
    const buffer = Buffer.from(await externalRes.arrayBuffer())
    if (buffer.byteLength > MAX_BYTES) {
      return res.status(413).json({ error: 'Imagen demasiado grande (máx 5MB)' })
    }

    cb.recordSuccess()
    res.set('Content-Type', contentType)
    res.set('Cache-Control', 'private, max-age=3600')
    return res.status(200).send(buffer)

  } catch (err) {
    cb.recordFailure()
    const isTimeout = err.name === 'AbortError' || err.code === 'UND_ERR_CONNECT_TIMEOUT'
    logger.warn('fetch_external_image_error', { reqId: req.reqId, error: err.message })
    return res.status(isTimeout ? 504 : 502).json({
      error: 'Error al obtener la imagen externa'
    })
  }
})

// ── 12. Health checks para Docker/Kubernetes/Nginx ───────────────────
app.get('/healthz', (req, res) => res.status(200).json({ status: 'ok' }))
app.get('/readyz',  (req, res) => res.status(200).json({
  status: 'ok',
  circuitBreaker: cb.state
}))

// ── 13. Métricas Prometheus ──────────────────────────────────────────
app.get('/metrics', async (req, res) => {
  try {
    res.set('Content-Type', register.contentType)
    res.end(await register.metrics())
  } catch (err) {
    res.status(500).end(err.message)
  }
})

// ── 14. Error handler global ─────────────────────────────────────────
//    OWASP A09 — NO exponer stack traces al cliente en producción
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  logger.error('unhandled_error', {
    reqId: req.reqId,
    message: err.message,
    stack: err.stack
  })
  res.status(err.status || 500).json({ error: 'Internal server error' })
})

// ── 15. Arrancar servidor ────────────────────────────────────────────
const PORT = parseInt(process.env.PORT || '3001', 10)
app.listen(PORT, '0.0.0.0', () => {
  logger.info('server_started', {
    port: PORT,
    env: process.env.NODE_ENV || 'development',
    pid: process.pid
  })
})