#!/bin/bash
cd /Users/bahram/ws/prj/filegrind/capns-py

# Create module directories
mkdir -p src/capns/urn src/capns/cap src/capns/media src/capns/bifaci

# URN module
git mv src/capns/cap_urn.py src/capns/urn/cap_urn.py
git mv src/capns/media_urn.py src/capns/urn/media_urn.py
git mv src/capns/cap_matrix.py src/capns/urn/cap_matrix.py

# Cap module
git mv src/capns/cap.py src/capns/cap/definition.py
git mv src/capns/caller.py src/capns/cap/caller.py
git mv src/capns/response.py src/capns/cap/response.py
git mv src/capns/registry.py src/capns/cap/registry.py
git mv src/capns/validation.py src/capns/cap/validation.py
git mv src/capns/schema_validation.py src/capns/cap/schema_validation.py

# Media module
git mv src/capns/media_spec.py src/capns/media/spec.py
git mv src/capns/media_registry.py src/capns/media/registry.py

# Bifaci module
git mv src/capns/cbor_frame.py src/capns/bifaci/frame.py
git mv src/capns/cbor_io.py src/capns/bifaci/io.py
git mv src/capns/manifest.py src/capns/bifaci/manifest.py
git mv src/capns/plugin_runtime.py src/capns/bifaci/plugin_runtime.py
git mv src/capns/plugin_host_runtime.py src/capns/bifaci/host_runtime.py
git mv src/capns/async_plugin_host.py src/capns/bifaci/async_plugin_host.py
git mv src/capns/plugin_relay.py src/capns/bifaci/relay.py
git mv src/capns/relay_switch.py src/capns/bifaci/relay_switch.py

# Create __init__.py files for new modules
touch src/capns/urn/__init__.py
touch src/capns/cap/__init__.py
touch src/capns/media/__init__.py
touch src/capns/bifaci/__init__.py

echo "File reorganization complete. Now update imports in src/capns/__init__.py"
