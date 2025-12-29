set -e
nimble build
set -a
source .env
set +a
./out/server