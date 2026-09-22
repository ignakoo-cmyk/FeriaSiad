'use strict'

/**
 * Middleware de autenticación por API Key.
 *
 * Protege endpoints sensibles exigiendo la cabecera:
 *   X-API-Key: <clave>
 *
 * Las claves válidas se leen de la variable de entorno API_KEYS
 * (lista separada por comas). Nunca se hardcodean en código.
 *
 * OWASP A01 – Control de Acceso
 * OWASP A07 – Fallos de Autenticación
 */

const VALID_API_KEYS = new Set(
  (process.env.API_KEYS || '').split(',').map(k => k.trim()).filter(Boolean)
)

/**
 * Middleware que exige API Key válida.
 * Responde 401 si falta o es inválida, sin revelar cuál de las dos.
 */
function requireApiKey (req, res, next) {
  const key = req.headers['x-api-key']

  if (!key || typeof key !== 'string' || !VALID_API_KEYS.has(key)) {
    return res.status(401).json({ error: 'Unauthorized' })
  }

  next()
}

module.exports = { requireApiKey }
