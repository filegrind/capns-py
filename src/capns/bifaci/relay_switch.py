"""RelaySwitch — Cap-aware routing multiplexer for multiple RelayMasters.

RelaySwitch sits above multiple RelayMasters and provides deterministic
request routing based on cap URN matching. It plays the same role for RelayMasters
that PluginHost plays for plugins.

## Architecture

```text
┌─────────────────────────────┐
│   Test Engine / API Client  │
└──────────────┬──────────────┘
               │
┌──────────────▼──────────────┐
│       RelaySwitch            │
│  • Aggregates capabilities   │
│  • Routes REQ by cap URN     │
│  • Routes frames by req_id   │
│  • Tracks peer requests      │
└─┬───┬───┬───┬───────────────┘
  │   │   │   │
  ▼   ▼   ▼   ▼
 RM  RM  RM  RM   (RelayMasters)
```

No fallbacks. No heuristics. No special cases. Just deterministic frame routing
based on URN matching and request ID tracking.
"""

import json
import threading
import queue
from typing import Optional, List, Tuple, Dict
from dataclasses import dataclass

from capns.bifaci.frame import Frame, FrameType, Limits, MessageId, DEFAULT_MAX_FRAME, DEFAULT_MAX_CHUNK, DEFAULT_MAX_REORDER_BUFFER
from capns.bifaci.io import FrameReader, FrameWriter, CborError
from capns.urn.cap_urn import CapUrn

# =============================================================================
# ERROR TYPES
# =============================================================================

class RelaySwitchError(Exception):
    """Base error for RelaySwitch"""
    pass


class NoHandlerError(RelaySwitchError):
    """No master found for capability"""
    def __init__(self, cap_urn: str):
        super().__init__(f"No handler for cap: {cap_urn}")
        self.cap_urn = cap_urn


class UnknownRequestError(RelaySwitchError):
    """Unknown request ID"""
    def __init__(self, request_id: str):
        super().__init__(f"Unknown request ID: {request_id}")
        self.request_id = request_id


class ProtocolError(RelaySwitchError):
    """Protocol violation"""
    pass


class AllMastersUnhealthyError(RelaySwitchError):
    """All masters are unhealthy"""
    def __init__(self):
        super().__init__("All relay masters are unhealthy")


# =============================================================================
# DATA STRUCTURES
# =============================================================================

@dataclass
class SocketPair:
    """Socket pair for master connection"""
    read: object  # file-like object for reading
    write: object  # file-like object for writing


@dataclass
class RoutingEntry:
    """Routing entry for request tracking"""
    source_master_idx: int  # Index of source master (ENGINE_SOURCE for engine-initiated)
    destination_master_idx: int  # Index of destination master


@dataclass
class MasterFrame:
    """Frame received from a master"""
    master_idx: int
    frame: Optional[Frame]
    error: Optional[Exception]


# Sentinel value for engine-initiated requests
ENGINE_SOURCE = 2**63 - 1


# =============================================================================
# RELAY SWITCH
# =============================================================================

class RelaySwitch:
    """Cap-aware routing multiplexer for multiple RelayMasters.

    Routes requests based on cap URN matching and tracks bidirectional request/response flows.
    """

    def __init__(self, sockets: List[SocketPair]):
        """Create a RelaySwitch from socket pairs.

        Args:
            sockets: List of socket pairs (one per master)

        Raises:
            RelaySwitchError: If construction fails
        """
        if not sockets:
            raise ProtocolError("RelaySwitch requires at least one master")

        self._masters: List[_MasterConnection] = []
        self._cap_table: List[Tuple[str, int]] = []  # (cap_urn, master_idx)
        self._request_routing: Dict[str, RoutingEntry] = {}
        self._peer_requests: set = set()  # Request IDs for peer-initiated requests
        self._aggregate_capabilities: bytes = b""
        self._negotiated_limits: Limits = Limits.default()
        self._lock = threading.Lock()

        # Channel for reader threads to send frames
        self._frame_queue: queue.Queue = queue.Queue()

        # Connect to all masters
        for master_idx, sock_pair in enumerate(sockets):
            reader = FrameReader(sock_pair.read)
            writer = FrameWriter(sock_pair.write)

            # Perform handshake (read initial RelayNotify)
            frame = reader.read()
            if frame is None or frame.frame_type != FrameType.RELAY_NOTIFY:
                raise ProtocolError("Expected RelayNotify during handshake")

            manifest = frame.relay_notify_manifest()
            limits = frame.relay_notify_limits()

            if manifest is None or limits is None:
                raise ProtocolError("RelayNotify missing manifest or limits")

            caps = _parse_capabilities_from_manifest(manifest)

            # Spawn reader thread for this master
            reader_thread = threading.Thread(
                target=self._reader_loop,
                args=(master_idx, reader),
                daemon=True
            )
            reader_thread.start()

            master_conn = _MasterConnection(
                socket_writer=writer,
                manifest=manifest,
                limits=limits,
                caps=caps,
                healthy=True,
                reader_handle=reader_thread
            )
            self._masters.append(master_conn)

        # Build initial routing tables
        self._rebuild_cap_table()
        self._rebuild_capabilities()
        self._rebuild_limits()

    def _reader_loop(self, master_idx: int, reader: FrameReader):
        """Reader thread loop for a master"""
        while True:
            try:
                frame = reader.read()
                if frame is None:
                    # EOF
                    self._frame_queue.put(MasterFrame(master_idx, None, None))
                    return

                # Handle RelayNotify here (intercept before sending to queue)
                if frame.frame_type == FrameType.RELAY_NOTIFY:
                    with self._lock:
                        manifest = frame.relay_notify_manifest()
                        limits = frame.relay_notify_limits()
                        if manifest is not None and limits is not None:
                            caps = _parse_capabilities_from_manifest(manifest)
                            self._masters[master_idx].manifest = manifest
                            self._masters[master_idx].limits = limits
                            self._masters[master_idx].caps = caps
                            self._rebuild_cap_table()
                            self._rebuild_capabilities()
                            self._rebuild_limits()
                    continue

                self._frame_queue.put(MasterFrame(master_idx, frame, None))
            except Exception as e:
                self._frame_queue.put(MasterFrame(master_idx, None, e))
                return

    def capabilities(self) -> bytes:
        """Get aggregate capabilities (union of all masters)"""
        with self._lock:
            return bytes(self._aggregate_capabilities)

    def limits(self) -> Limits:
        """Get negotiated limits (minimum across all masters)"""
        with self._lock:
            return self._negotiated_limits

    def send_to_master(self, frame: Frame, preferred_cap: Optional[str] = None) -> None:
        """Send a frame to the appropriate master (engine → plugin direction)

        Routes REQ by cap URN. Routes continuation frames by request ID.

        Args:
            frame: The frame to send
            preferred_cap: Optional capability URN for exact routing.
                          When provided, routes to the master whose registered cap
                          is equivalent to this URN. When None, uses standard
                          accepts + closest-specificity routing.

        Raises:
            NoHandlerError: No master found for cap
            UnknownRequestError: Unknown request ID for continuation frame
        """
        with self._lock:
            if frame.frame_type == FrameType.REQ:
                # Find master for this cap
                dest_idx = self._find_master_for_cap(frame.cap, preferred_cap)
                if dest_idx is None:
                    raise NoHandlerError(frame.cap)

                # Register routing (source = engine)
                self._request_routing[frame.id.to_string()] = RoutingEntry(
                    source_master_idx=ENGINE_SOURCE,
                    destination_master_idx=dest_idx
                )

                self._masters[dest_idx].socket_writer.write(frame)

            elif frame.frame_type in (FrameType.STREAM_START, FrameType.CHUNK,
                                     FrameType.STREAM_END, FrameType.END, FrameType.ERR):
                # Continuation frames route by request ID
                entry = self._request_routing.get(frame.id.to_string())
                if entry is None:
                    raise UnknownRequestError(frame.id.to_string())

                dest_idx = entry.destination_master_idx
                self._masters[dest_idx].socket_writer.write(frame)

                # Cleanup on terminal frames for peer responses
                is_terminal = frame.frame_type in (FrameType.END, FrameType.ERR)
                if is_terminal and frame.id.to_string() in self._peer_requests:
                    del self._request_routing[frame.id.to_string()]
                    self._peer_requests.discard(frame.id.to_string())

            else:
                # Other frame types pass through to first master (or error)
                if self._masters:
                    self._masters[0].socket_writer.write(frame)

    def read_from_masters(self) -> Optional[Frame]:
        """Read the next frame from any master (plugin → engine direction).

        Blocks until a frame is available. Returns None when all masters have closed.
        Peer requests (plugin → plugin) are handled internally and not returned.
        """
        while True:
            # Block on queue - reader threads send frames here
            master_frame = self._frame_queue.get()

            if master_frame.error is not None:
                # Error reading from master
                self._handle_master_death(master_frame.master_idx)
                continue

            if master_frame.frame is None:
                # EOF from master
                self._handle_master_death(master_frame.master_idx)
                # Check if all masters are dead
                with self._lock:
                    if all(not m.healthy for m in self._masters):
                        return None
                continue

            # Handle the frame
            result_frame = self._handle_master_frame(master_frame.master_idx, master_frame.frame)
            if result_frame is not None:
                return result_frame
            # Peer request was handled internally, continue reading

    def _find_master_for_cap(self, cap_urn: str, preferred_cap: Optional[str] = None) -> Optional[int]:
        """Find master index that can handle a capability.

        Args:
            cap_urn: The capability URN to find a handler for
            preferred_cap: Optional capability URN for exact routing.
                          When provided, uses comparable matching (broader) and prefers
                          masters whose registered cap is equivalent to this URN.
                          When None, uses standard accepts + closest-specificity routing.

        Returns:
            Master index, or None if no handler found
        """
        try:
            request_urn = CapUrn.from_string(cap_urn)
        except:
            return None

        request_specificity = request_urn.specificity()

        # Parse preferred cap URN if provided
        preferred_urn = None
        if preferred_cap:
            try:
                preferred_urn = CapUrn.from_string(preferred_cap)
            except:
                pass

        # Collect ALL matching masters with their specificity scores
        # When preferred_cap is set, use is_comparable (broader); otherwise accepts (standard)
        matches: List[Tuple[int, int, bool]] = []  # (master_idx, specificity, is_preferred)

        for registered_cap, master_idx in self._cap_table:
            try:
                registered_urn = CapUrn.from_string(registered_cap)
            except:
                continue

            # Determine if this is a match
            if preferred_urn:
                # Comparable: either side accepts the other (broader match set)
                is_match = request_urn.accepts(registered_urn) or registered_urn.accepts(request_urn)
            else:
                # Standard: request is pattern, registered cap is instance
                is_match = request_urn.accepts(registered_urn)

            if is_match:
                specificity = registered_urn.specificity()
                # Check if this registered cap is equivalent to the preferred cap
                is_preferred = False
                if preferred_urn:
                    is_preferred = preferred_urn.accepts(registered_urn) and registered_urn.accepts(preferred_urn)
                matches.append((master_idx, specificity, is_preferred))

        if not matches:
            return None

        # If any match is preferred, pick the first preferred match
        for idx, _, is_pref in matches:
            if is_pref:
                return idx

        # Fall back to closest-specificity (ties broken by first match)
        min_distance = min(abs(s - request_specificity) for _, s, _ in matches)
        for idx, s, _ in matches:
            if abs(s - request_specificity) == min_distance:
                return idx

        return None

    def _handle_master_frame(self, source_idx: int, frame: Frame) -> Optional[Frame]:
        """Handle a frame from a master. Returns frame to return to engine, or None if handled internally."""
        with self._lock:
            if frame.frame_type == FrameType.REQ:
                # Peer request: plugin → plugin via switch (no preference)
                dest_idx = self._find_master_for_cap(frame.cap, None)
                if dest_idx is None:
                    raise NoHandlerError(frame.cap)

                # Register routing (source = plugin's master)
                self._request_routing[frame.id.to_string()] = RoutingEntry(
                    source_master_idx=source_idx,
                    destination_master_idx=dest_idx
                )
                self._peer_requests.add(frame.id.to_string())

                self._masters[dest_idx].socket_writer.write(frame)

                # Do NOT return to engine (internal routing)
                return None

            elif frame.frame_type in (FrameType.STREAM_START, FrameType.CHUNK,
                                     FrameType.STREAM_END, FrameType.END,
                                     FrameType.ERR, FrameType.LOG):
                entry = self._request_routing.get(frame.id.to_string())
                if entry is not None and entry.source_master_idx != ENGINE_SOURCE:
                    # Response to peer request
                    dest_idx = entry.source_master_idx
                    is_terminal = frame.frame_type in (FrameType.END, FrameType.ERR)

                    self._masters[dest_idx].socket_writer.write(frame)

                    if is_terminal and frame.id.to_string() not in self._peer_requests:
                        del self._request_routing[frame.id.to_string()]

                    return None

                # Response to engine request
                is_terminal = frame.frame_type in (FrameType.END, FrameType.ERR)
                if is_terminal and frame.id.to_string() not in self._peer_requests:
                    del self._request_routing[frame.id.to_string()]

                return frame

            else:
                # Unknown frame type - return to engine
                return frame

    def _handle_master_death(self, master_idx: int):
        """Handle master death: ERR pending requests, mark unhealthy, rebuild caps"""
        with self._lock:
            if not self._masters[master_idx].healthy:
                return  # Already handled

            self._masters[master_idx].healthy = False

            # ERR all pending requests to this master
            to_remove = []
            for req_id, entry in self._request_routing.items():
                if entry.destination_master_idx == master_idx:
                    # TODO: Send ERR to source
                    to_remove.append(req_id)

            for req_id in to_remove:
                del self._request_routing[req_id]
                self._peer_requests.discard(req_id)

            # Rebuild cap table without dead master
            self._rebuild_cap_table()
            self._rebuild_capabilities()
            self._rebuild_limits()

    def _rebuild_cap_table(self):
        """Rebuild capability routing table from all healthy masters"""
        self._cap_table.clear()
        for idx, master in enumerate(self._masters):
            if master.healthy:
                for cap in master.caps:
                    self._cap_table.append((cap, idx))

    def _rebuild_capabilities(self):
        """Rebuild aggregate capabilities manifest (union with deduplication)"""
        all_caps = set()
        for master in self._masters:
            if master.healthy:
                all_caps.update(master.caps)

        manifest = {
            "capabilities": sorted(list(all_caps))
        }
        self._aggregate_capabilities = json.dumps(manifest).encode("utf-8")

    def _rebuild_limits(self):
        """Rebuild negotiated limits (minimum across all masters)"""
        min_frame = 2**63 - 1
        min_chunk = 2**63 - 1
        min_reorder = 2**63 - 1

        for master in self._masters:
            if master.healthy:
                if master.limits.max_frame < min_frame:
                    min_frame = master.limits.max_frame
                if master.limits.max_chunk < min_chunk:
                    min_chunk = master.limits.max_chunk
                if master.limits.max_reorder_buffer < min_reorder:
                    min_reorder = master.limits.max_reorder_buffer

        if min_frame == 2**63 - 1:
            min_frame = DEFAULT_MAX_FRAME
        if min_chunk == 2**63 - 1:
            min_chunk = DEFAULT_MAX_CHUNK
        if min_reorder == 2**63 - 1:
            min_reorder = DEFAULT_MAX_REORDER_BUFFER

        self._negotiated_limits = Limits(max_frame=min_frame, max_chunk=min_chunk, max_reorder_buffer=min_reorder)


# =============================================================================
# INTERNAL TYPES
# =============================================================================

@dataclass
class _MasterConnection:
    """Connection to a single RelayMaster"""
    socket_writer: FrameWriter
    manifest: bytes
    limits: Limits
    caps: List[str]
    healthy: bool
    reader_handle: threading.Thread


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _parse_capabilities_from_manifest(manifest: bytes) -> List[str]:
    """Parse capability URNs from manifest JSON"""
    try:
        parsed = json.loads(manifest.decode("utf-8"))
        caps_value = parsed.get("capabilities", [])
        if not isinstance(caps_value, list):
            raise ProtocolError(f"Manifest capabilities must be array, got {type(caps_value)}")
        return [str(cap) for cap in caps_value]
    except json.JSONDecodeError as e:
        raise ProtocolError(f"Failed to parse manifest JSON: {e}")
