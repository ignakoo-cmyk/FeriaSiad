'use strict'

/**
 * Logging estructurado con Winston.
 *
 * Emite JSON por stdout → compatible con ELK, Loki, Cloud Logging.
 * Nunca expone stack traces al cliente (OWASP A09).
 *
 * Incluye middleware de request logging con:
 *   - Correlation ID por request (crypto.randomUUID)
 *   - Método, ruta, status code, duración en ms, IP
 */

const { createLogger, format, transports } = require('winston')
const crypto = require('crypto')

const logger = createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: format.combine(
    format.timestamp({ format: 'YYYY-MM-DDTHH:mm:ss.SSSZ' }),
    format.errors({ stack: true }),
    format.json()
  ),
  defaultMeta: { service: 'uah-faceai', version: '1.0.0' },
  transports: [
    new transports.Console({
      silent: process.env.NODE_ENV === 'test'
    })
  ]
})

/**
 * Middleware Express que registra cada request HTTP.
 * Adjunta un reqId único para correlacionar logs.
 */
function requestLogger (req, res, next) {
  const start = Date.now()
  const reqId = crypto.randomUUID()
  req.reqId = reqId
  res.setHeader('X-Request-Id', reqId)

  res.on('finish', () => {
    const durationMs = Date.now() - start
    const level = res.statusCode >= 500 ? 'error'
      : res.statusCode >= 400 ? 'warn'
        : 'info'

    logger[level]('http_request', {
      reqId,
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      durationMs,
      ip: req.ip,
      userAgent: req.headers['user-agent'] || ''
    })
  })

  next()
}

module.exports = { logger, requestLogger }
