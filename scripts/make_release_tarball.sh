#!/usr/bin/env bash
# Build a relocatable pg_tci release tarball (shared lib + SQL + control + docs slice).
# Run on the target OS/arch (Linux CI or Linux builder). Requires PG_CONFIG for PG18.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

PG_CONFIG="${PG_CONFIG:-$(command -v pg_config)}"
VERSION="$(grep -E '^default_version' pg_tci.control | sed -E "s/.*'([^']+)'.*/\1/")"
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
OUT_DIR="${OUT_DIR:-${ROOT}/out}"
STAGE="${OUT_DIR}/pg_tci-${VERSION}-${OS}-${ARCH}"
TARBALL="${OUT_DIR}/pg_tci-${VERSION}-${OS}-${ARCH}.tar.gz"

mkdir -p "${OUT_DIR}"
rm -rf "${STAGE}"
mkdir -p "${STAGE}/lib" "${STAGE}/share/extension" "${STAGE}/docs" "${STAGE}/examples" "${STAGE}/scripts"

echo "Building with ${PG_CONFIG} ($(${PG_CONFIG} --version))"
make clean
make PG_CONFIG="${PG_CONFIG}"
make PG_CONFIG="${PG_CONFIG}" DESTDIR="${STAGE}/.install" install

# PGXS DESTDIR layout varies; copy known artifacts from build dir + sql/
shopt -s nullglob
for f in pg_tci.so pg_tci.dylib; do
  if [ -f "${f}" ]; then
    cp -a "${f}" "${STAGE}/lib/"
  fi
done
# Also pick from DESTDIR if present
find "${STAGE}/.install" -type f \( -name 'pg_tci.so' -o -name 'pg_tci.dylib' \) \
  -exec cp -a {} "${STAGE}/lib/" \; 2>/dev/null || true
find "${STAGE}/.install" -type f \( -name 'pg_tci.control' -o -name 'pg_tci--*.sql' \) \
  -exec cp -a {} "${STAGE}/share/extension/" \; 2>/dev/null || true

cp -a pg_tci.control "${STAGE}/share/extension/"
cp -a sql/pg_tci--*.sql "${STAGE}/share/extension/"
cp -a README.md LICENSE CHANGELOG.md SECURITY.md "${STAGE}/"
cp -a docs/api.md docs/limitations.md docs/operations.md docs/quickstart.md \
  docs/when-not-to-use.md docs/architecture.md docs/benchmarks.md \
  docs/images "${STAGE}/docs/" 2>/dev/null || true
cp -a examples/*.sql examples/*.sh "${STAGE}/examples/" 2>/dev/null || true
cp -a scripts/make_release_tarball.sh "${STAGE}/scripts/"

cat > "${STAGE}/INSTALL.txt" <<EOF
pg_tci ${VERSION} — free open-source external preview (not production GA)

1. Copy lib/pg_tci.so (or .dylib) into PostgreSQL pkglibdir:
     $(${PG_CONFIG} --pkglibdir)
2. Copy share/extension/* into:
     $(${PG_CONFIG} --sharedir)/extension
3. CREATE EXTENSION pg_tci;  -- or ALTER EXTENSION pg_tci UPDATE;

Requires PostgreSQL 18 and superuser. See docs/when-not-to-use.md
EOF

# Require shared library in the stage
if ! compgen -G "${STAGE}/lib/pg_tci.so" > /dev/null \
   && ! compgen -G "${STAGE}/lib/pg_tci.dylib" > /dev/null; then
  echo "ERROR: pg_tci shared library missing under ${STAGE}/lib" >&2
  exit 1
fi

rm -rf "${STAGE}/.install"
tar -C "${OUT_DIR}" -czf "${TARBALL}" "$(basename "${STAGE}")"
(
  cd "${OUT_DIR}"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$(basename "${TARBALL}")" | tee "$(basename "${TARBALL}").sha256"
  else
    shasum -a 256 "$(basename "${TARBALL}")" | tee "$(basename "${TARBALL}").sha256"
  fi
)

echo "Wrote ${TARBALL}"
echo "Stage ${STAGE}"
