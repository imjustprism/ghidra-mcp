#[derive(Debug, Clone, Copy)]
pub struct PacketRow {
    pub id: u8,
    pub name: &'static str,
    pub direction: &'static str,
    pub notes: &'static str,
    pub handler_hint: &'static str,
}

/// DSO custom + common `RakNet` IDs used by the client. Distilled from
/// `DSO-Reconstruction/Drakensang_RaknetProtocol` research notes.
pub static PACKETS: &[PacketRow] = &[
    PacketRow {
        id: 0x00,
        name: "ID_CONNECTED_PING",
        direction: "bidir",
        notes: "Connected ping",
        handler_hint: "",
    },
    PacketRow {
        id: 0x03,
        name: "ID_CONNECTED_PONG",
        direction: "bidir",
        notes: "Connected pong",
        handler_hint: "",
    },
    PacketRow {
        id: 0x05,
        name: "ID_OPEN_CONNECTION_REQUEST_1",
        direction: "C→S",
        notes: "RakNet handshake step 1; magic + protocol + MTU padding",
        handler_hint: "",
    },
    PacketRow {
        id: 0x06,
        name: "ID_OPEN_CONNECTION_REPLY_1",
        direction: "S→C",
        notes: "Handshake reply 1; GUID + security + MTU",
        handler_hint: "",
    },
    PacketRow {
        id: 0x07,
        name: "ID_OPEN_CONNECTION_REQUEST_2",
        direction: "C→S",
        notes: "Handshake step 2",
        handler_hint: "",
    },
    PacketRow {
        id: 0x08,
        name: "ID_OPEN_CONNECTION_REPLY_2",
        direction: "S→C",
        notes: "Handshake reply 2",
        handler_hint: "",
    },
    PacketRow {
        id: 0x09,
        name: "ID_CONNECTION_REQUEST",
        direction: "C→S",
        notes: "Post-open connection request",
        handler_hint: "",
    },
    PacketRow {
        id: 0x10,
        name: "ID_CONNECTION_REQUEST_ACCEPTED",
        direction: "S→C",
        notes: "Also seen as remote disconnect notify in some DSO handler tables",
        handler_hint: "RakNetClient disconnect path / accept",
    },
    PacketRow {
        id: 0x11,
        name: "ID_CONNECTION_ATTEMPT_FAILED",
        direction: "S→C",
        notes: "Connection attempt failed",
        handler_hint: "RakNetClient::HandleConnectionFailed",
    },
    PacketRow {
        id: 0x12,
        name: "ID_NO_FREE_INCOMING_CONNECTIONS",
        direction: "S→C",
        notes: "Server full",
        handler_hint: "ignored or logged",
    },
    PacketRow {
        id: 0x13,
        name: "ID_NEW_INCOMING_CONNECTION",
        direction: "C→S",
        notes: "New incoming connection (handshake complete)",
        handler_hint: "",
    },
    PacketRow {
        id: 0x14,
        name: "ID_NO_FREE_INCOMING_CONNECTIONS_ALT",
        direction: "S→C",
        notes: "Server full (alt id observed)",
        handler_hint: "logs warning",
    },
    PacketRow {
        id: 0x15,
        name: "ID_DISCONNECTION_NOTIFICATION",
        direction: "S→C",
        notes: "Server actively disconnected this client",
        handler_hint: "RakNetClient::HandleDisconnectionByServer",
    },
    PacketRow {
        id: 0x16,
        name: "ID_CONNECTION_LOST",
        direction: "S→C",
        notes: "Lost connection to server",
        handler_hint: "RakNetClient::HandleConnectionLost",
    },
    PacketRow {
        id: 0x19,
        name: "ID_INCOMPATIBLE_PROTOCOL_VERSION",
        direction: "S→C",
        notes: "Incompatible protocol / custom",
        handler_hint: "dispatch FUN_* variant",
    },
    PacketRow {
        id: 0x1b,
        name: "ID_TIMESTAMP",
        direction: "bidir",
        notes: "Timestamp / keepalive; may wrap real type at offset +10",
        handler_hint: "special-case read byte 10",
    },
    PacketRow {
        id: 0x82,
        name: "PACKET_SERVER_IDENTIFY",
        direction: "S→C",
        notes: "Service discovery: DrasaCharacterService / ChatService / map server name (ASCII)",
        handler_hint: "RakNetClient service identify path",
    },
    PacketRow {
        id: 0x83,
        name: "PACKET_TIME_SYNC",
        direction: "S→C",
        notes: "Server time synchronization",
        handler_hint: "RakNetClient::HandleTimeSync",
    },
    PacketRow {
        id: 0x84,
        name: "PACKET_DATA_TRANSFER",
        direction: "S→C",
        notes: "Large data / frame-set style custom payload (arg 0)",
        handler_hint: "FUN_* (this, packet, 0)",
    },
    PacketRow {
        id: 0x85,
        name: "PACKET_GAME_STATE",
        direction: "S→C",
        notes: "World state / entities / position; 40-80ms heartbeat; subtypes 0x8e/0x8f/0x89",
        handler_hint: "FUN_* (this, packet, 1) / game state dispatch",
    },
    PacketRow {
        id: 0x86,
        name: "PACKET_MAP_DATA",
        direction: "S→C",
        notes: "Map name (duplicated) + 0xffffffff terminator; e.g. a0000_char",
        handler_hint: "map change handler",
    },
    PacketRow {
        id: 0x87,
        name: "PACKET_STATE_RESET",
        direction: "S→C",
        notes: "Resets internal RakNetClient field (e.g. field @0x120 = 0)",
        handler_hint: "state reset",
    },
    PacketRow {
        id: 0x88,
        name: "PACKET_MAP_SIGNAL",
        direction: "S→C",
        notes: "Map ready / load trigger; sets state + optional callback",
        handler_hint: "map load validation",
    },
    PacketRow {
        id: 0x89,
        name: "PACKET_CUSTOM_0x89",
        direction: "S→C",
        notes: "Custom event logic (under-documented)",
        handler_hint: "FUN_* custom",
    },
    PacketRow {
        id: 0x8a,
        name: "PACKET_CLIENT_IDENTIFY",
        direction: "C→S",
        notes: "Client auth: DrasaOnlineClient / ChatClient name + session + token (protobuf-ish)",
        handler_hint: "client identify send path",
    },
    PacketRow {
        id: 0x8b,
        name: "PACKET_PLAYER_ACTION",
        direction: "C→S",
        notes: "Player input/actions (KM/LM/MM codes) or hardware config + spellbar dump",
        handler_hint: "player action / local config",
    },
    PacketRow {
        id: 0x8d,
        name: "PACKET_SESSION_SIGNAL",
        direction: "C→S",
        notes: "Session/map-ready signal after 0x86/0x88",
        handler_hint: "session ready",
    },
    PacketRow {
        id: 0x8e,
        name: "PACKET_CUSTOM_0x8e",
        direction: "S→C",
        notes: "Custom logic / also appears as 0x85 subtype",
        handler_hint: "FUN_* custom",
    },
    PacketRow {
        id: 0xa0,
        name: "ID_NACK",
        direction: "bidir",
        notes: "NACK range/single sequence",
        handler_hint: "RakNet reliability",
    },
    PacketRow {
        id: 0xc0,
        name: "ID_ACK",
        direction: "bidir",
        notes: "ACK range/single sequence",
        handler_hint: "RakNet reliability",
    },
];

pub fn lookup(id: Option<u8>, query: Option<&str>) -> Vec<&'static PacketRow> {
    let q = query.map(str::trim).filter(|s| !s.is_empty());
    let q_lower = q.map(str::to_ascii_lowercase);
    PACKETS
        .iter()
        .filter(|row| {
            if let Some(id) = id {
                if row.id != id {
                    return false;
                }
            }
            if let Some(ref ql) = q_lower {
                let name = row.name.to_ascii_lowercase();
                let notes = row.notes.to_ascii_lowercase();
                let handler = row.handler_hint.to_ascii_lowercase();
                if !name.contains(ql.as_str())
                    && !notes.contains(ql.as_str())
                    && !handler.contains(ql.as_str())
                {
                    return false;
                }
            }
            id.is_some() || q_lower.is_some()
        })
        .collect()
}

pub fn overview_markdown() -> String {
    r"# DSO / Nebula3 RakNet overview

Credit: distilled from DSO-Reconstruction/Drakensang_RaknetProtocol (educational RE notes).

## Layers
- Application: custom messages **0x82–0x8e**
- Transport: RakNet reliable ordered (UDP)
- Services: Character / Chat / Game (multi-port; chat often 2191)

## Wire conventions
- Strings: length-prefixed (u16) then ASCII bytes
- Offline magic (16 bytes): `00 ff ff 00 fe fe fe fe fd fd fd fd 12 34 56 78`
- GUID: 8 bytes
- First payload byte often = message type

## Handshake (RakNet)
1. C→S Open Connection Request 1 (`0x05`)
2. S→C Open Connection Reply 1 (`0x06`)
3. C→S Open Connection Request 2 (`0x07`)
4. S→C Open Connection Reply 2 (`0x08`)
5. C→S Connection Request (`0x09`)
6. S→C Connection Request Accepted (`0x10`)
7. C→S New Incoming Connection (`0x13`)
8. Ping/Pong (`0x00` / `0x03`)

## After connect
- S→C `0x82` service name (`DrasaCharacterService`, `ChatService`, …)
- C→S `0x8a` client identify (`DrasaOnlineClient` / `ChatClient` + session/token)
- Map load: S→C `0x86` map name → `0x88` map signal → C→S `0x8d` ready
- Game loop: S→C `0x85` state (~40–80ms) ↔ C→S `0x8b` actions; `0x1b` timestamp/keepalive

## Ghidra tips
1. `nebula_engine_survey` then `name_from_n_assert`
2. `find_function_by_string` value=`DrasaOnlineClient` / `RakNet` / service names
3. `raknet_packet_lookup` id=`0x8a` while decompiling dispatch switches
4. `tls_singleton_map` for live client singletons after `live_attach`
"
    .to_owned()
}

pub fn packet_ids_markdown() -> String {
    use std::fmt::Write as _;
    let mut s = String::from(
        "# DSO RakNet packet IDs\n\n| id | name | dir | notes | handler hint |\n|---|---|---|---|---|\n",
    );
    for row in PACKETS {
        let _ = writeln!(
            s,
            "| `0x{:02x}` | {} | {} | {} | {} |",
            row.id, row.name, row.direction, row.notes, row.handler_hint
        );
    }
    s.push_str(
        "\nUse `raknet_packet_lookup` for filtered queries. Handler addresses vary by build.\n",
    );
    s
}

pub fn packet_flows_markdown() -> String {
    r"# DSO in-game packet flows

## Service discovery + auth
```
S→C 0x82  service name (DrasaCharacterService | ChatService | …)
C→S 0x8a  client name + session id + auth token
```

## Map change
```
S→C 0x86  map name (duplicated) + ff ff ff ff
S→C 0x88  map load signal / map id
C→S 0x8d  client ready
S→C 0x85  full world state
```

## Combat / interact
```
C→S 0x8b  action code (e.g. KM / LM / MM) + target id + flags + timestamp
S→C 0x85  entity HP / loot / inventory subtype updates
```

## Heartbeat
```
S→C 0x85 every 40–80ms (positions as float32 LE x3, entity blocks, names)
C→S ACK promptly; timestamps echoed on 0x8b within ~±500ms
```

## Multi-service reconnect
Client may open a second RakNet handshake on another port (chat vs character)
while old socket still receives 0x85, then tear down the old connection.

## Reliability
- Frame sets encapsulate messages with flags (0x60 = reliable ordered)
- ACK `0xC0` / NACK `0xA0` with u24 sequence ranges
"
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_by_hex_id() {
        let rows = lookup(Some(0x8a), None);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "PACKET_CLIENT_IDENTIFY");
    }

    #[test]
    fn lookup_by_name_substring() {
        let rows = lookup(None, Some("time sync"));
        assert!(rows.iter().any(|r| r.id == 0x83));
    }

    #[test]
    fn lookup_requires_filter() {
        assert!(lookup(None, None).is_empty());
        assert!(lookup(None, Some("   ")).is_empty());
    }

    #[test]
    fn overview_mentions_magic() {
        assert!(overview_markdown().contains("00 ff ff 00"));
    }
}
