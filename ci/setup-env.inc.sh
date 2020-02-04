set -euxo pipefail

mkdir -p installs
LOCAL_INSTALLS=/tmp/rnp-local-installs
ln -s "$GITHUB_WORKSPACE/installs" /tmp/rnp-local-installs
echo "::set-env name=CACHE_DIR::installs"
echo "::set-env name=BOTAN_INSTALL::$GITHUB_WORKSPACE/installs/botan"
echo "::set-env name=BUNDLE_INSTALL::$GITHUB_WORKSPACE/installs/bundle"

