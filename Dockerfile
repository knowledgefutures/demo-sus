# SUS is a single zero-dependency file. No install, no build.
FROM node:24-slim AS production
WORKDIR /app

COPY sus.mjs ./

# Content store lives in a volume so data survives container restarts.
ENV NODE_ENV=production
ENV PORT=8080
ENV SUS_DATA=/data
VOLUME ["/data"]
EXPOSE 8080

# Node 24 has a global fetch, so no curl/wget is needed in the image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://localhost:8080/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "sus.mjs"]
