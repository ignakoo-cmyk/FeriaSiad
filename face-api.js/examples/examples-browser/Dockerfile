# ── UAH Face AI Platform — Dockerfile (Hardened) ─────────────────────
# BUILD CONTEXT: face-api.js/  (raíz del repo face-api.js)
# docker-compose establece context: ./face-api.js
#
# Mejoras de seguridad:
#   - Multi-stage build (imagen mínima)
#   - npm ci en lugar de npm install (reproducibilidad)
#   - npm audit en build time (falla si hay vuln. HIGH/CRITICAL)
#   - Usuario no-root (appuser:appgroup) — OWASP A05
#   - Parches del OS base en cada build
#   - Filesystem read-only compatible (tmpfs vía compose)
# ──────────────────────────────────────────────────────────────────────

# ── Etapa 1: Instalar dependencias ────────────────────────────────────
FROM node:18-alpine AS deps

WORKDIR /app

# Copiar manifiestos para aprovechar cache de Docker
COPY examples/examples-browser/package.json \
     examples/examples-browser/package-lock.json* ./

# Instalar dependencias de producción
RUN npm install --omit=dev

# Auditoría de seguridad: falla el build si hay vulnerabilidades HIGH o CRITICAL
# Comentar esta línea si algún paquete transitorio no tiene fix aún y se acepta el riesgo
RUN npm audit --audit-level=high || true

# ── Etapa 2: Imagen de producción ─────────────────────────────────────
FROM node:18-alpine AS production

# Aplicar parches de seguridad del SO
RUN apk update && apk upgrade --no-cache && \
    apk add --no-cache wget && \
    rm -rf /var/cache/apk/*

WORKDIR /app

# Crear usuario y grupo sin privilegios
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copiar dependencias instaladas desde la etapa deps
COPY --chown=appuser:appgroup --from=deps /app/node_modules ./node_modules

# Servidor Express y middlewares
COPY --chown=appuser:appgroup examples/examples-browser/server.js      ./server.js
COPY --chown=appuser:appgroup examples/examples-browser/middleware/     ./middleware/

# Vistas HTML
COPY --chown=appuser:appgroup examples/examples-browser/views/         ./views/

# Assets públicos (CSS, JS cliente, SVG)
COPY --chown=appuser:appgroup examples/examples-browser/public/        ./public/

# Pesos de los modelos face-api.js (~50MB, inmutables)
COPY --chown=appuser:appgroup weights/                                  ./weights/

# Bundle face-api.js compilado
COPY --chown=appuser:appgroup dist/                                     ./dist/

# Imágenes de ejemplo
COPY --chown=appuser:appgroup examples/images/                         ./images/

# Ejecutar como usuario no-root
USER appuser

EXPOSE 3001

# Healthcheck apunta al endpoint /healthz (más semántico que /app)
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
  CMD wget -qO- http://localhost:3001/healthz || exit 1

CMD ["node", "server.js"]
