use std::borrow::Cow;

use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    handler::server::wrapper::Parameters,
    model::{
        CacheScope, CallToolResult, CompleteRequestParams, CompleteResult, CompletionInfo,
        ContentBlock, DiscoverResult, Implementation, ListResourcesResult, ListToolsResult,
        PaginatedRequestParams, PromptMessage, ProtocolVersion, ReadResourceRequestParams,
        ReadResourceResponse, ReadResourceResult, Reference, Resource, ResourceContents, Role,
        ServerCapabilities, ServerInfo,
    },
    prompt, prompt_handler, prompt_router, schemars,
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::client::{BridgeError, GhidraHttp};

const SUPPORTED_PROTOCOL_VERSIONS: &[ProtocolVersion] = &[
    ProtocolVersion::V_2026_07_28,
    ProtocolVersion::V_2025_11_25,
    ProtocolVersion::V_2025_06_18,
    ProtocolVersion::V_2025_03_26,
    ProtocolVersion::V_2024_11_05,
];
const CATALOG_TTL_MS: u64 = 300_000;
const STATIC_RESOURCE_TTL_MS: u64 = 3_600_000;
const LIVE_RESOURCE_TTL_MS: u64 = 2_000;
const COMPLETE_LIMIT: usize = 20;

#[derive(Clone)]
pub struct GhidraServer {
    http: GhidraHttp,
}

fn ok_text(s: impl Into<String>) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(s.into())])
}

fn tool_fail(e: BridgeError) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(bridge_message(e))])
}

fn resource_err(e: BridgeError) -> ErrorData {
    ErrorData::internal_error(bridge_message(e), None)
}

fn bridge_message(e: BridgeError) -> String {
    match &e {
        BridgeError::Http(h) if h.is_connect() => format!(
            "{e} — cannot reach the GhidraMCP plugin. Is Ghidra running with the \
             ghidra-mcp extension enabled and a program open?"
        ),
        BridgeError::Http(h) if h.is_timeout() => {
            format!("{e} — request timed out. Raise --timeout-secs for long operations")
        }
        _ => e.to_string(),
    }
}

type Params = Vec<(&'static str, String)>;

fn de_opt_u32<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum NumOrStr {
        Num(u32),
        Str(String),
    }
    match Option::<NumOrStr>::deserialize(deserializer)? {
        None => Ok(None),
        Some(NumOrStr::Num(n)) => Ok(Some(n)),
        Some(NumOrStr::Str(s)) => {
            let t = s.trim();
            if t.is_empty() {
                return Ok(None);
            }
            t.strip_prefix("0x")
                .or_else(|| t.strip_prefix("0X"))
                .map_or_else(|| t.parse::<u32>(), |h| u32::from_str_radix(h, 16))
                .map(Some)
                .map_err(serde::de::Error::custom)
        }
    }
}

fn de_opt_clean<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Clean {
        Bool(bool),
        Str(String),
        Num(u32),
    }
    Ok(match Option::<Clean>::deserialize(deserializer)? {
        None => None,
        Some(Clean::Bool(true)) => Some("1".into()),
        Some(Clean::Bool(false)) => Some("0".into()),
        Some(Clean::Num(n)) => Some(n.to_string()),
        Some(Clean::Str(s)) => {
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_owned())
            }
        }
    })
}

fn de_opt_bool<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum BoolOrStr {
        Bool(bool),
        Str(String),
    }
    match Option::<BoolOrStr>::deserialize(deserializer)? {
        None => Ok(None),
        Some(BoolOrStr::Bool(b)) => Ok(Some(b)),
        Some(BoolOrStr::Str(s)) => match s.trim().to_ascii_lowercase().as_str() {
            "" => Ok(None),
            "true" | "1" | "yes" | "on" => Ok(Some(true)),
            "false" | "0" | "no" | "off" => Ok(Some(false)),
            other => Err(serde::de::Error::custom(format!("invalid bool: {other}"))),
        },
    }
}

trait ToParams {
    fn into_params(self) -> Params;
}

fn flag(value: bool) -> String {
    if value { "1" } else { "0" }.to_owned()
}

impl ToParams for Page {
    fn into_params(self) -> Params {
        let mut p = vec![
            ("offset", self.offset.to_string()),
            ("limit", self.limit.to_string()),
        ];
        if let Some(f) = self.fmt {
            p.push(("fmt", f));
        }
        if let Some(prog) = self.program {
            p.push(("program", prog));
        }
        if let Some(fields) = self.fields {
            p.push(("fields", fields));
        }
        if let Some(grep) = self.grep {
            p.push(("grep", grep));
        }
        if self.count == Some(true) {
            p.push(("count", "1".to_owned()));
        }
        if let Some(cap) = self.max_bytes {
            p.push(("max_bytes", cap.to_string()));
        }
        p
    }
}

impl ToParams for Address {
    fn into_params(self) -> Params {
        vec![("address", self.address)]
    }
}

impl ToParams for AddressPage {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        p.push(("address", self.address));
        p
    }
}

impl ToParams for Xrefs {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        p.push(("target", self.target));
        if let Some(d) = self.direction {
            p.push(("direction", d));
        }
        p
    }
}

impl ToParams for Coverage {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        if let Some(o) = self.op {
            p.push(("op", o));
        }
        if !self.path.is_empty() {
            p.push(("path", self.path));
        }
        if !self.path_a.is_empty() {
            p.push(("path_a", self.path_a));
        }
        if !self.path_b.is_empty() {
            p.push(("path_b", self.path_b));
        }
        p
    }
}

impl ToParams for SearchFunctions {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        p.push(("query", self.query));
        p
    }
}

impl ToParams for Rename {
    fn into_params(self) -> Params {
        let mut p = vec![("new_name", self.new_name)];
        if let Some(k) = self.kind {
            p.push(("kind", k));
        }
        if let Some(o) = self.old_name {
            p.push(("old_name", o));
        }
        if let Some(a) = self.address {
            p.push(("address", a));
        }
        if let Some(f) = self.function_name {
            p.push(("function_name", f));
        }
        p
    }
}

impl ToParams for AddressComment {
    fn into_params(self) -> Params {
        vec![("address", self.address), ("comment", self.comment)]
    }
}

impl ToParams for LiveWriteRegister {
    fn into_params(self) -> Params {
        vec![("register", self.register), ("value", self.value)]
    }
}

impl ToParams for DebuggerLaunch {
    fn into_params(self) -> Params {
        let mut p = vec![("offer", self.offer)];
        if let Some(a) = self.args {
            p.push(("args", a));
        }
        p
    }
}

impl ToParams for LiveProcesses {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        if let Some(n) = self.name {
            p.push(("name", n));
        }
        p
    }
}

impl ToParams for LiveAttach {
    fn into_params(self) -> Params {
        let mut p: Params = Vec::new();
        if let Some(n) = self.name {
            p.push(("name", n));
        }
        if let Some(pid) = self.pid {
            p.push(("pid", pid));
        }
        p
    }
}

impl ToParams for LuaExec {
    fn into_params(self) -> Params {
        let mut p = vec![("code", self.code)];
        if let Some(s) = self.state {
            p.push(("state", s));
        }
        if let Some(f) = self.func {
            p.push(("fn", f));
        }
        if let Some(fr) = self.freeze {
            p.push(("freeze", flag(fr)));
        }
        if let Some(h) = self.hook {
            p.push(("hook", h));
        }
        if let Some(g) = self.gettop {
            p.push(("gettop", g));
        }
        if let Some(l) = self.loadbuffer {
            p.push(("loadbuffer", l));
        }
        if let Some(pc) = self.pcall {
            p.push(("pcall", pc));
        }
        if let Some(s) = self.settop {
            p.push(("settop", s));
        }
        p
    }
}

impl ToParams for GhidraEval {
    fn into_params(self) -> Params {
        let mut p = vec![("code", self.code)];
        if let Some(l) = self.lang {
            p.push(("lang", l));
        }
        if let Some(c) = self.commit {
            p.push(("commit", flag(c)));
        }
        p
    }
}

impl ToParams for AnalysisNote {
    fn into_params(self) -> Params {
        let mut p = vec![("text", self.text)];
        if let Some(a) = self.address {
            p.push(("address", a));
        }
        if let Some(c) = self.category {
            p.push(("category", c));
        }
        p
    }
}

impl ToParams for RefineFunction {
    fn into_params(self) -> Params {
        let mut p = vec![("address", self.address)];
        if let Some(c) = self.commit {
            p.push(("commit", flag(c)));
        }
        p
    }
}

impl ToParams for Scan {
    fn into_params(self) -> Params {
        let mut p = vec![("op", self.op)];
        if !self.scan_id.is_empty() {
            p.push(("scan_id", self.scan_id));
        }
        if let Some(v) = self.value {
            p.push(("value", v));
        }
        if let Some(t) = self.value_type {
            p.push(("type", t));
        }
        if self.all.unwrap_or(false) {
            p.push(("all", "1".to_string()));
        }
        if let Some(t) = self.tolerance {
            p.push(("tolerance", t));
        }
        if let Some(m) = self.max_mb {
            p.push(("max_mb", m.to_string()));
        }
        if self.exclude_modules.unwrap_or(false) {
            p.push(("exclude_modules", "1".to_string()));
        }
        if let Some(c) = self.comparator {
            p.push(("comparator", c));
        }
        if let Some(l) = self.limit {
            p.push(("limit", l.to_string()));
        }
        p
    }
}

impl ToParams for BatchItems {
    fn into_params(self) -> Params {
        vec![("items", self.items)]
    }
}

impl ToParams for SetPrototype {
    fn into_params(self) -> Params {
        vec![
            ("function_address", self.function_address),
            ("prototype", self.prototype),
        ]
    }
}

impl ToParams for SetLocalVarType {
    fn into_params(self) -> Params {
        vec![
            ("function_address", self.function_address),
            ("variable_name", self.variable_name),
            ("new_type", self.new_type),
        ]
    }
}

impl ToParams for ReadBytes {
    fn into_params(self) -> Params {
        vec![
            ("address", self.address),
            ("length", self.length.to_string()),
        ]
    }
}

impl ToParams for PatchBytes {
    fn into_params(self) -> Params {
        vec![
            ("address", self.address),
            ("hex", self.hex),
            (
                "disassemble",
                if self.disassemble { "1" } else { "0" }.to_owned(),
            ),
        ]
    }
}

impl ToParams for Search {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        p.push(("kind", self.kind));
        p.push(("query", self.query));
        if let Some(start) = self.start {
            p.push(("start", start));
        }
        p
    }
}

impl ToParams for CreateLabel {
    fn into_params(self) -> Params {
        vec![("address", self.address), ("name", self.name)]
    }
}

impl ToParams for HexDump {
    fn into_params(self) -> Params {
        vec![
            ("address", self.address),
            ("length", self.length.to_string()),
        ]
    }
}

impl ToParams for NopRange {
    fn into_params(self) -> Params {
        vec![
            ("address", self.address),
            ("length", self.length.to_string()),
        ]
    }
}

impl ToParams for ExportBinary {
    fn into_params(self) -> Params {
        vec![("path", self.path)]
    }
}

impl ToParams for WriteArtifact {
    fn into_params(self) -> Params {
        vec![("path", self.path), ("content", self.content)]
    }
}

impl ToParams for ApplyGdt {
    fn into_params(self) -> Params {
        vec![("path", self.path)]
    }
}

impl ToParams for XorDecrypt {
    fn into_params(self) -> Params {
        vec![
            ("address", self.address),
            ("length", self.length.to_string()),
            ("key", self.key),
        ]
    }
}

impl ToParams for ImportMemoryDump {
    fn into_params(self) -> Params {
        vec![("address", self.address), ("path", self.path)]
    }
}

impl ToParams for FindEncodedStrings {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        p.push(("address", self.address));
        p.push(("length", self.length.to_string()));
        p.push(("min_len", self.min_len.to_string()));
        p
    }
}

impl ToParams for FindApiHashes {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        p.push(("algo", self.algo.as_str().to_owned()));
        p
    }
}

impl ToParams for Emulate {
    fn into_params(self) -> Params {
        let mut p = vec![
            ("start", self.start),
            ("max_steps", self.max_steps.to_string()),
            ("capture_length", self.capture_length.to_string()),
            ("commit", flag(self.commit)),
        ];
        if let Some(v) = self.stop {
            p.push(("stop", v));
        }
        if let Some(v) = self.skip_calls {
            p.push(("skip_calls", v));
        }
        if let Some(v) = self.capture_addr {
            p.push(("capture_addr", v));
        }
        p
    }
}

impl ToParams for EmuStart {
    fn into_params(self) -> Params {
        let mut p = vec![("start", self.start)];
        if let Some(s) = self.stack {
            p.push(("stack", s));
        }
        p
    }
}

impl ToParams for EmulateFunction {
    fn into_params(self) -> Params {
        let mut p = vec![
            ("function_address", self.function_address),
            ("capture_length", self.capture_length.to_string()),
        ];
        if let Some(a) = self.args {
            p.push(("args", a));
        }
        if let Some(m) = self.max_steps {
            p.push(("max_steps", m.to_string()));
        }
        if let Some(c) = self.capture_addr {
            p.push(("capture_addr", c));
        }
        p
    }
}

impl ToParams for AssembleCode {
    fn into_params(self) -> Params {
        vec![("address", self.address), ("assembly", self.assembly)]
    }
}

impl ToParams for ApiCallSequence {
    fn into_params(self) -> Params {
        let mut p = vec![("address", self.address)];
        if let Some(a) = self.api_only {
            p.push(("api_only", if a { "1".to_owned() } else { "0".to_owned() }));
        }
        p
    }
}

impl ToParams for VmDescriptorArgs {
    fn into_params(self) -> Params {
        let mut p = vec![("table_address", self.table_address)];
        if let Some(m) = self.max_entries {
            p.push(("max_entries", m.to_string()));
        }
        p
    }
}

impl ToParams for RecoverDecodedStrings {
    fn into_params(self) -> Params {
        let mut p = vec![("function_address", self.function_address)];
        if let Some(a) = self.args {
            p.push(("args", a));
        }
        if let Some(m) = self.min_len {
            p.push(("min_len", m.to_string()));
        }
        if let Some(m) = self.max_steps {
            p.push(("max_steps", m.to_string()));
        }
        if let Some(o) = self.output_addr {
            p.push(("output_addr", o));
        }
        if let Some(o) = self.output_length {
            p.push(("output_length", o.to_string()));
        }
        p
    }
}

impl ToParams for EmuSession {
    fn into_params(self) -> Params {
        let mut p = vec![("op", self.op), ("emu_id", self.emu_id)];
        if let Some(c) = self.count {
            p.push(("count", c.to_string()));
        }
        if let Some(s) = self.stop {
            p.push(("stop", s));
        }
        if let Some(m) = self.max_steps {
            p.push(("max_steps", m.to_string()));
        }
        if self.full.unwrap_or(false) {
            p.push(("full", "1".to_string()));
        }
        if let Some(r) = self.register {
            p.push(("register", r));
        }
        if let Some(v) = self.value {
            p.push(("value", v));
        }
        if let Some(a) = self.address {
            p.push(("address", a));
        }
        if let Some(l) = self.length {
            p.push(("length", l.to_string()));
        }
        if let Some(h) = self.hex {
            p.push(("hex", h));
        }
        p
    }
}

impl ToParams for DebuggerRegisters {
    fn into_params(self) -> Params {
        let mut p: Params = self.thread.into_iter().map(|t| ("thread", t)).collect();
        if self.full.unwrap_or(false) {
            p.push(("full", "1".to_string()));
        }
        p
    }
}

impl ToParams for HighEntropyRegions {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        p.push(("threshold", self.threshold.to_string()));
        p.push(("window", self.window.to_string()));
        p
    }
}

impl ToParams for ListStrings {
    fn into_params(self) -> Params {
        let mut p = vec![
            ("offset", self.offset.to_string()),
            ("limit", self.limit.to_string()),
        ];
        if let Some(f) = self.filter {
            p.push(("filter", f));
        }
        if self.regex.unwrap_or(false) {
            p.push(("regex", "1".to_owned()));
        }
        if self.xrefs.unwrap_or(false) {
            p.push(("xrefs", "1".to_owned()));
        }
        if let Some(f) = self.fmt {
            p.push(("fmt", f));
        }
        if let Some(prog) = self.program {
            p.push(("program", prog));
        }
        p
    }
}

impl ToParams for DemangleSymbol {
    fn into_params(self) -> Params {
        vec![("mangled", self.mangled)]
    }
}

impl ToParams for ImportCHeader {
    fn into_params(self) -> Params {
        let mut p = vec![("header", self.header)];
        if let Some(c) = self.category {
            p.push(("category", c));
        }
        p
    }
}

impl ToParams for CreateStruct {
    fn into_params(self) -> Params {
        vec![("name", self.name), ("fields", self.fields)]
    }
}

impl ToParams for CreateUnion {
    fn into_params(self) -> Params {
        vec![("name", self.name), ("fields", self.fields)]
    }
}

impl ToParams for CreateEnum {
    fn into_params(self) -> Params {
        vec![
            ("name", self.name),
            ("size", self.size.to_string()),
            ("values", self.values),
        ]
    }
}

impl ToParams for CallgraphMermaid {
    fn into_params(self) -> Params {
        let mut p = vec![("address", self.address)];
        if let Some(d) = self.depth {
            p.push(("depth", d.to_string()));
        }
        if let Some(dir) = self.direction {
            p.push(("direction", dir));
        }
        if let Some(m) = self.max_nodes {
            p.push(("max_nodes", m.to_string()));
        }
        if let Some(f) = self.format {
            p.push(("format", f));
        }
        p
    }
}

impl ToParams for StructDiagramArgs {
    fn into_params(self) -> Params {
        let mut p = Params::new();
        if let Some(f) = self.filter {
            p.push(("filter", f));
        }
        if let Some(m) = self.max {
            p.push(("max", m.to_string()));
        }
        p
    }
}

impl ToParams for FindOrphanGaps {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        p.push(("min_size", self.min_size.to_string()));
        p
    }
}

impl ToParams for DebuggerListModules {
    fn into_params(self) -> Params {
        self.trace.into_iter().map(|t| ("trace", t)).collect()
    }
}

impl ToParams for DebuggerThreadFilter {
    fn into_params(self) -> Params {
        self.thread.into_iter().map(|t| ("thread", t)).collect()
    }
}

impl ToParams for DebuggerReadMemory {
    fn into_params(self) -> Params {
        vec![
            ("address", self.address),
            ("length", self.length.to_string()),
        ]
    }
}

impl ToParams for PointerScanArgs {
    fn into_params(self) -> Params {
        let mut p = vec![("target", self.target)];
        if let Some(m) = self.max_offset {
            p.push(("max_offset", m.to_string()));
        }
        if let Some(l) = self.limit {
            p.push(("limit", l.to_string()));
        }
        p
    }
}

impl ToParams for ReadPointerPath {
    fn into_params(self) -> Params {
        let mut p = vec![("base", self.base)];
        if let Some(o) = self.offsets {
            p.push(("offsets", o));
        }
        if let Some(v) = self.value_len {
            p.push(("value_len", v.to_string()));
        }
        p
    }
}

impl ToParams for LiveReadStruct {
    fn into_params(self) -> Params {
        vec![("address", self.address), ("schema", self.schema)]
    }
}

impl ToParams for DebuggerSetBreakpoint {
    fn into_params(self) -> Params {
        let mut p = vec![("address", self.address)];
        if let Some(k) = self.kind {
            p.push(("kind", k));
        }
        p
    }
}

impl ToParams for MagicConstantsRange {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        if let Some(v) = self.min {
            p.push(("min", v));
        }
        if let Some(v) = self.max {
            p.push(("max", v));
        }
        p
    }
}

impl ToParams for NeutralizeAntiDebug {
    fn into_params(self) -> Params {
        vec![("apply", flag(self.apply))]
    }
}

impl ToParams for IdiomSimplifierInput {
    fn into_params(self) -> Params {
        vec![("address", self.address), ("apply", flag(self.apply))]
    }
}

impl ToParams for MakeSignature {
    fn into_params(self) -> Params {
        let mut p = vec![
            ("address", self.address),
            ("min_len", self.min_len.to_string()),
            ("max_len", self.max_len.to_string()),
            ("format", self.format),
        ];
        if let Some(m) = self.mode {
            p.push(("mode", m));
        }
        p
    }
}

impl ToParams for FindRopGadgets {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        if let Some(f) = self.filter {
            p.push(("filter", f));
        }
        if let Some(m) = self.max_instrs {
            p.push(("max_instrs", m.to_string()));
        }
        p
    }
}

impl ToParams for FindFunctionByString {
    fn into_params(self) -> Params {
        let mut p = vec![
            ("value", self.value),
            ("max", self.max.to_string()),
            ("format", self.format),
        ];
        if self.regex.unwrap_or(false) {
            p.push(("regex", "1".to_string()));
        }
        if self.callers.unwrap_or(false) {
            p.push(("callers", "1".to_string()));
        }
        p
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema, Default)]
pub struct Page {
    #[serde(default)]
    pub offset: u32,
    #[serde(default = "default_limit")]
    pub limit: u32,
    #[schemars(description = "Output format: tsv (default), csv, json, or verbose.")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fmt: Option<String>,
    #[schemars(
        description = "Target a specific open program by name or sha256 instead of the active one."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    #[schemars(
        description = "Return only these columns, comma-separated, in this order (e.g. \
                       fields=address,name). Every table names its columns in the '# cols=' header. \
                       The cheapest way to cut response size when you need one or two of them."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<String>,
    #[schemars(
        description = "Case-insensitive regex; only matching rows are returned. The reply reports \
                       'matched=N of scanned=M', so you still learn how much was searched. Filter \
                       here instead of pulling the whole table back and reading it."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grep: Option<String>,
    #[schemars(
        description = "Return only the match count, no rows. Use it to size a query before deciding \
                       how to page it."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<bool>,
    #[schemars(
        description = "Cap the reply in bytes (1000..2000000, default 200000). Truncation happens at \
                       a row boundary."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u32>,
}
const fn default_limit() -> u32 {
    100
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct Address {
    pub address: String,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct AssembleCode {
    pub address: String,
    pub assembly: String,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct ApiCallSequence {
    pub address: String,
    #[serde(
        default,
        deserialize_with = "de_opt_bool",
        skip_serializing_if = "Option::is_none"
    )]
    pub api_only: Option<bool>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct VmDescriptorArgs {
    pub table_address: String,
    #[serde(
        default,
        deserialize_with = "de_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_entries: Option<u32>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct AddressPage {
    pub address: String,
    #[serde(flatten)]
    pub page: Page,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct Xrefs {
    #[schemars(description = "\"both\" (default), \"to\", or \"from\".")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    pub target: String,
    #[serde(flatten)]
    pub page: Page,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct SearchFunctions {
    pub query: String,
    #[serde(flatten)]
    pub page: Page,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct Decompile {
    #[schemars(
        description = "Function name OR address. An interior address resolves to the enclosing function; a value that is not a mapped VA is auto-treated as an RVA (`image_base`+value), or force it with `rva:0x2d202c`."
    )]
    pub target: String,
    #[schemars(
        description = "Noise filter: true/1 = strip casts and WARNING blocks; std/aggressive/2 = also drop std::string SSO / length-error noise that buries HTTP/crypto logic."
    )]
    #[serde(
        default,
        deserialize_with = "de_opt_clean",
        skip_serializing_if = "Option::is_none"
    )]
    pub clean: Option<String>,
    #[schemars(
        description = "Line window: skip this many lines of the output (paged/grep output is 1-based line-numbered)."
    )]
    #[serde(
        default,
        deserialize_with = "de_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub offset: Option<u32>,
    #[schemars(description = "Line window: return at most this many lines.")]
    #[serde(
        default,
        deserialize_with = "de_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub limit: Option<u32>,
    #[schemars(
        description = "Return only lines matching this regex (line-numbered), instead of the whole body."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grep: Option<String>,
    #[schemars(
        description = "Target a specific open program by name or sha256 instead of the active one."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
}

impl ToParams for Decompile {
    fn into_params(self) -> Params {
        let mut p = vec![("target", self.target)];
        if let Some(c) = self.clean
            && !c.is_empty()
            && c != "0"
            && !c.eq_ignore_ascii_case("false")
        {
            p.push(("clean", c));
        }
        if let Some(o) = self.offset {
            p.push(("offset", o.to_string()));
        }
        if let Some(l) = self.limit {
            p.push(("limit", l.to_string()));
        }
        if let Some(g) = self.grep {
            p.push(("grep", g));
        }
        if let Some(prog) = self.program {
            p.push(("program", prog));
        }
        p
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct Rename {
    #[schemars(description = "What to rename: \"function\" (default), \"data\", or \"variable\".")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub new_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_name: Option<String>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct AddressComment {
    pub address: String,
    pub comment: String,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct SetPrototype {
    pub function_address: String,
    pub prototype: String,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct SetLocalVarType {
    pub function_address: String,
    pub variable_name: String,
    pub new_type: String,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct ReadBytes {
    pub address: String,
    #[serde(default = "default_read_length")]
    pub length: u32,
}
const fn default_read_length() -> u32 {
    64
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct PatchBytes {
    pub address: String,
    pub hex: String,
    #[serde(default)]
    pub disassemble: bool,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct Search {
    #[schemars(
        description = "\"bytes\" (hex pattern, ?? wildcards), \"string\" (substring of DEFINED program strings only), \"text\" (literal substring scanned across raw memory as ASCII and UTF-16LE — finds undefined/embedded strings that \"string\" misses), or \"signature\" (AOB dialect)."
    )]
    pub kind: String,
    #[schemars(description = "The hex/AOB pattern (bytes/signature) or the substring (string).")]
    pub query: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    #[serde(flatten)]
    pub page: Page,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct CreateLabel {
    pub address: String,
    pub name: String,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct HexDump {
    pub address: String,
    #[serde(default = "default_dump_length")]
    pub length: u32,
}
const fn default_dump_length() -> u32 {
    128
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct NopRange {
    pub address: String,
    pub length: u32,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct ExportBinary {
    pub path: String,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct WriteArtifact {
    pub path: String,
    pub content: String,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct ApplyGdt {
    pub path: String,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct XorDecrypt {
    pub address: String,
    pub length: u32,
    pub key: String,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct ImportMemoryDump {
    pub address: String,
    pub path: String,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct FindEncodedStrings {
    pub address: String,
    #[serde(default = "default_scan_length")]
    pub length: u32,
    #[serde(default = "default_min_len")]
    pub min_len: u32,
    #[serde(flatten)]
    pub page: Page,
}
const fn default_scan_length() -> u32 {
    0x10000
}
const fn default_min_len() -> u32 {
    6
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct RecoverHiddenStrings {
    #[schemars(
        description = "Optional function address. Omit to scan the whole program for decrypt loops."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[schemars(description = "auto (default), splitmix, rolling_xor, imm, or all.")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algo: Option<String>,
    #[serde(
        default,
        deserialize_with = "de_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub min_len: Option<u32>,
    #[serde(
        default,
        deserialize_with = "de_opt_bool",
        skip_serializing_if = "Option::is_none"
    )]
    pub apply: Option<bool>,
    #[serde(flatten)]
    pub page: Page,
}

impl ToParams for RecoverHiddenStrings {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        if let Some(a) = self.address {
            p.push(("address", a));
        }
        if let Some(a) = self.algo {
            p.push(("algo", a));
        }
        if let Some(m) = self.min_len {
            p.push(("min_len", m.to_string()));
        }
        if self.apply.unwrap_or(false) {
            p.push(("apply", "1".to_owned()));
        }
        p
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct RecoverAuthSurface {
    #[serde(flatten)]
    pub page: Page,
}

impl ToParams for RecoverAuthSurface {
    fn into_params(self) -> Params {
        self.page.into_params()
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct FunctionBehavior {
    pub address: String,
    #[serde(flatten)]
    pub page: Page,
}

impl ToParams for FunctionBehavior {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        p.push(("address", self.address));
        p
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct ExtractIocs {
    #[schemars(description = "defined (default), raw (scan .rdata/.data ASCII+UTF-16), or both.")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(flatten)]
    pub page: Page,
}

impl ToParams for ExtractIocs {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        if let Some(s) = self.scope {
            p.push(("scope", s));
        }
        p
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct SampleIntake {
    #[serde(
        default,
        deserialize_with = "de_opt_bool",
        skip_serializing_if = "Option::is_none"
    )]
    pub deep: Option<bool>,
    #[serde(flatten)]
    pub page: Page,
}

impl ToParams for SampleIntake {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        if self.deep.unwrap_or(false) {
            p.push(("deep", "1".to_owned()));
        }
        p
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct RecoverCryptoRecipe {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(flatten)]
    pub page: Page,
}

impl ToParams for RecoverCryptoRecipe {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        if let Some(a) = self.address {
            p.push(("address", a));
        }
        p
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct ExportYara {
    #[schemars(description = "yara (default) or tsv/json/csv")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(
        default,
        deserialize_with = "de_opt_bool",
        skip_serializing_if = "Option::is_none"
    )]
    pub deep: Option<bool>,
    #[serde(flatten)]
    pub page: Page,
}

impl ToParams for ExportYara {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        if let Some(f) = self.format {
            p.push(("format", f));
        }
        if let Some(n) = self.name {
            p.push(("name", n));
        }
        if self.deep.unwrap_or(false) {
            p.push(("deep", "1".to_owned()));
        }
        p
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct DecodeKeystream {
    pub address: String,
    #[serde(default = "default_keystream_len")]
    pub length: u32,
    pub seed: String,
    #[schemars(description = "splitmix (default), rolling_xor, xor8")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algo: Option<String>,
    #[serde(default = "default_keystream_inc")]
    pub increment: u32,
}

const fn default_keystream_len() -> u32 {
    64
}
const fn default_keystream_inc() -> u32 {
    1
}

impl ToParams for DecodeKeystream {
    fn into_params(self) -> Params {
        let mut p = vec![
            ("address", self.address),
            ("length", self.length.to_string()),
            ("seed", self.seed),
            ("increment", self.increment.to_string()),
        ];
        if let Some(a) = self.algo {
            p.push(("algo", a));
        }
        p
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema, Default, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum HashAlgo {
    #[default]
    Fnv1a,
    Fnv1aLower,
    Djb2,
    Crc32,
}

impl HashAlgo {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Fnv1a => "fnv1a",
            Self::Fnv1aLower => "fnv1a_lower",
            Self::Djb2 => "djb2",
            Self::Crc32 => "crc32",
        }
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema, Default)]
pub struct FindApiHashes {
    #[serde(default)]
    pub algo: HashAlgo,
    #[serde(flatten)]
    pub page: Page,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct Emulate {
    pub start: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop: Option<String>,
    #[serde(default = "default_max_steps")]
    pub max_steps: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_calls: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_addr: Option<String>,
    #[serde(default)]
    pub capture_length: u32,
    #[serde(default)]
    pub commit: bool,
}
const fn default_max_steps() -> u32 {
    500_000
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct EmuStart {
    pub start: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack: Option<String>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct EmulateFunction {
    pub function_address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<String>,
    #[serde(
        default,
        deserialize_with = "de_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_steps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_addr: Option<String>,
    #[serde(default)]
    pub capture_length: u32,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct RecoverDecodedStrings {
    pub function_address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<String>,
    #[serde(
        default,
        deserialize_with = "de_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub min_len: Option<u32>,
    #[serde(
        default,
        deserialize_with = "de_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_steps: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_addr: Option<String>,
    #[serde(
        default,
        deserialize_with = "de_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub output_length: Option<u32>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct EmuSession {
    #[schemars(
        description = "Which session operation to run (see the tool description for the verbs)."
    )]
    pub op: String,
    pub emu_id: String,
    #[serde(
        default,
        deserialize_with = "de_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop: Option<String>,
    #[serde(
        default,
        deserialize_with = "de_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_steps: Option<u32>,
    #[serde(
        default,
        deserialize_with = "de_opt_bool",
        skip_serializing_if = "Option::is_none"
    )]
    pub full: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub register: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(
        default,
        deserialize_with = "de_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub length: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hex: Option<String>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema, Default)]
pub struct DebuggerRegisters {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<String>,
    #[serde(
        default,
        deserialize_with = "de_opt_bool",
        skip_serializing_if = "Option::is_none"
    )]
    pub full: Option<bool>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema, Default)]
pub struct HighEntropyRegions {
    #[serde(default = "default_threshold")]
    pub threshold: f64,
    #[serde(default = "default_window")]
    pub window: u32,
    #[serde(flatten)]
    pub page: Page,
}
const fn default_threshold() -> f64 {
    7.5
}
const fn default_window() -> u32 {
    256
}

#[derive(Deserialize, Serialize, schemars::JsonSchema, Default)]
pub struct ListStrings {
    #[serde(default)]
    pub offset: u32,
    #[serde(default = "default_strings_limit")]
    pub limit: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    #[serde(
        default,
        deserialize_with = "de_opt_bool",
        skip_serializing_if = "Option::is_none"
    )]
    pub regex: Option<bool>,
    #[serde(
        default,
        deserialize_with = "de_opt_bool",
        skip_serializing_if = "Option::is_none"
    )]
    pub xrefs: Option<bool>,
    #[schemars(description = "Output format: tsv (default), csv, json, or verbose.")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fmt: Option<String>,
    #[schemars(
        description = "Target a specific open program by name or sha256 instead of the active one."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
}
const fn default_strings_limit() -> u32 {
    2000
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct DemangleSymbol {
    pub mangled: String,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct ImportCHeader {
    pub header: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct CreateStruct {
    pub name: String,
    pub fields: String,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct CreateUnion {
    pub name: String,
    pub fields: String,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct CreateEnum {
    pub name: String,
    #[serde(default = "default_enum_size")]
    pub size: u32,
    pub values: String,
}
const fn default_enum_size() -> u32 {
    4
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct CallgraphMermaid {
    pub address: String,
    #[serde(
        default,
        deserialize_with = "de_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub depth: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    #[serde(
        default,
        deserialize_with = "de_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_nodes: Option<u32>,
    #[schemars(description = "\"mermaid\" (default) or \"dot\" (Graphviz).")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct StructDiagramArgs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    #[serde(
        default,
        deserialize_with = "de_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub max: Option<u32>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema, Default)]
pub struct FindOrphanGaps {
    #[serde(default = "default_orphan_min_size")]
    pub min_size: u32,
    #[serde(flatten)]
    pub page: Page,
}
const fn default_orphan_min_size() -> u32 {
    16
}

#[derive(Deserialize, Serialize, schemars::JsonSchema, Default)]
pub struct DebuggerListModules {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<String>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema, Default)]
pub struct DebuggerThreadFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread: Option<String>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema, Default)]
pub struct MagicConstantsRange {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<String>,
    #[serde(flatten)]
    pub page: Page,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema, Default)]
pub struct NeutralizeAntiDebug {
    #[serde(default)]
    pub apply: bool,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct IdiomSimplifierInput {
    pub address: String,
    #[serde(default)]
    pub apply: bool,
}

fn default_format() -> String {
    "ida".to_owned()
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct MakeSignature {
    pub address: String,
    #[serde(default)]
    pub min_len: u32,
    #[serde(default)]
    pub max_len: u32,
    #[serde(default = "default_format")]
    pub format: String,
    #[schemars(
        description = "\"bytes\" (default, wildcarded AOB) or \"semantic\" (emulation behavioral fingerprint)."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct FindRopGadgets {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    #[serde(
        default,
        deserialize_with = "de_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_instrs: Option<u32>,
    #[serde(flatten)]
    pub page: Page,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct FindFunctionByString {
    pub value: String,
    #[serde(default = "default_ffbs_max")]
    pub max: u32,
    #[serde(default = "default_format")]
    pub format: String,
    #[schemars(
        description = "Treat value as a case-insensitive regex (match string families like `Daily|Reshuffle|Timed` in one call)."
    )]
    #[serde(
        default,
        deserialize_with = "de_opt_bool",
        skip_serializing_if = "Option::is_none"
    )]
    pub regex: Option<bool>,
    #[schemars(
        description = "When true, also emit one-level callers of each hit (callers=comma names, caller_n=count) — string → fn → callers in one call."
    )]
    #[serde(
        default,
        deserialize_with = "de_opt_bool",
        skip_serializing_if = "Option::is_none"
    )]
    pub callers: Option<bool>,
}
const fn default_ffbs_max() -> u32 {
    20
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct DebuggerReadMemory {
    pub address: String,
    #[serde(default = "default_read_length")]
    pub length: u32,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct PointerScanArgs {
    pub target: String,
    #[serde(
        default,
        deserialize_with = "de_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_offset: Option<u32>,
    #[serde(
        default,
        deserialize_with = "de_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub limit: Option<u32>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct ReadPointerPath {
    pub base: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offsets: Option<String>,
    #[serde(
        default,
        deserialize_with = "de_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub value_len: Option<u32>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct LiveReadStruct {
    pub address: String,
    pub schema: String,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct DebuggerSetBreakpoint {
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct LiveWriteRegister {
    pub register: String,
    pub value: String,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct DebuggerLaunch {
    pub offer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<String>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct LiveProcesses {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(flatten)]
    pub page: Page,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct LiveAttach {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<String>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct LuaExec {
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(rename = "fn", default, skip_serializing_if = "Option::is_none")]
    pub func: Option<String>,
    #[serde(
        default,
        deserialize_with = "de_opt_bool",
        skip_serializing_if = "Option::is_none"
    )]
    pub freeze: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hook: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gettop: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loadbuffer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pcall: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settop: Option<String>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct GhidraEval {
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lang: Option<String>,
    #[serde(
        default,
        deserialize_with = "de_opt_bool",
        skip_serializing_if = "Option::is_none"
    )]
    pub commit: Option<bool>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct AnalysisNote {
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct RefineFunction {
    pub address: String,
    #[serde(
        default,
        deserialize_with = "de_opt_bool",
        skip_serializing_if = "Option::is_none"
    )]
    pub commit: Option<bool>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct Scan {
    #[schemars(description = "Which scan lifecycle step to run.")]
    pub op: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scan_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub value_type: Option<String>,
    #[serde(
        default,
        deserialize_with = "de_opt_bool",
        skip_serializing_if = "Option::is_none"
    )]
    pub all: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tolerance: Option<String>,
    #[serde(
        default,
        deserialize_with = "de_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_mb: Option<u32>,
    #[serde(
        default,
        deserialize_with = "de_opt_bool",
        skip_serializing_if = "Option::is_none"
    )]
    pub exclude_modules: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comparator: Option<String>,
    #[serde(
        default,
        deserialize_with = "de_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub limit: Option<u32>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct BatchItems {
    pub items: String,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct VariableEdit {
    pub variable_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_type: Option<String>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct DiffPrograms {
    pub program_b: String,
    #[serde(flatten)]
    pub page: Page,
}

impl ToParams for DiffPrograms {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        p.push(("program_b", self.program_b));
        p
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct PropagateMatches {
    pub program_b: String,
    #[serde(default)]
    pub apply: bool,
}

impl ToParams for PropagateMatches {
    fn into_params(self) -> Params {
        vec![("program_b", self.program_b), ("apply", flag(self.apply))]
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct DiffFunctions {
    pub address_a: String,
    pub address_b: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program_b: Option<String>,
    #[schemars(
        description = "\"structural\" (default) score table, \"semantic\" emulation I/O match, or \"source\" side-by-side decompiled C for both functions (clean=true by default)."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[schemars(description = "For mode=source only: strip decompiler noise (default true).")]
    #[serde(
        default,
        deserialize_with = "de_opt_bool",
        skip_serializing_if = "Option::is_none"
    )]
    pub clean: Option<bool>,
}

impl ToParams for DiffFunctions {
    fn into_params(self) -> Params {
        let mut p = vec![("address_a", self.address_a), ("address_b", self.address_b)];
        if let Some(b) = self.program_b {
            p.push(("program_b", b));
        }
        if let Some(m) = self.mode {
            p.push(("mode", m));
        }
        if let Some(c) = self.clean {
            p.push(("clean", if c { "1" } else { "0" }.to_string()));
        }
        p
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct NebulaContainerLayout {
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variable: Option<String>,
}

impl ToParams for NebulaContainerLayout {
    fn into_params(self) -> Params {
        let mut p = vec![("address", self.address)];
        if let Some(v) = self.variable {
            p.push(("variable", v));
        }
        p
    }
}

const fn default_prove_offset_max() -> u32 {
    25
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct ProveOffsetArgs {
    #[schemars(
        description = "Function VA/RVA/rva:/interior address to prove every offset inside. Give this OR field/class."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[schemars(
        description = "Field name as it appears in the n_assert text, e.g. summonMonsterAmount, commands, currState. Searches the whole program's assert strings."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[schemars(
        description = "Class name filter, e.g. GameActorShiftedSkill or Skills::SkillManager. Matched against the class the assert's FUNCSIG belongs to."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    #[schemars(
        description = "Drop every row that is not confidence=exact (default false, so ambiguous and unprovable asserts stay visible)."
    )]
    #[serde(
        default,
        deserialize_with = "de_opt_bool",
        skip_serializing_if = "Option::is_none"
    )]
    pub proven_only: Option<bool>,
    #[schemars(
        description = "Max functions to decompile on the search path (default 25, hard cap 200)."
    )]
    #[serde(default = "default_prove_offset_max")]
    pub max: u32,
    #[serde(flatten)]
    pub page: Page,
}

impl ToParams for ProveOffsetArgs {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        p.push(("max", self.max.to_string()));
        if let Some(a) = self.address.filter(|s| !s.trim().is_empty()) {
            p.push(("address", a));
        }
        if let Some(f) = self.field.filter(|s| !s.trim().is_empty()) {
            p.push(("field", f));
        }
        if let Some(c) = self.class.filter(|s| !s.trim().is_empty()) {
            p.push(("class", c));
        }
        if let Some(v) = self.proven_only {
            p.push(("proven_only", flag(v)));
        }
        p
    }
}

const fn default_context_count() -> u32 {
    4
}

const fn default_context_bytes() -> u32 {
    16
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct AddressContextArgs {
    #[schemars(
        description = "VA, RVA or rva:… address to frame. Interior and unaligned addresses are the point."
    )]
    pub address: String,
    #[schemars(
        description = "Instructions of context either side of the containing instruction (default 4, max 64)."
    )]
    #[serde(default = "default_context_count")]
    pub count: u32,
    #[schemars(
        description = "Bytes to dump from the containing instruction start and from the function entry (default 16, max 256)."
    )]
    #[serde(default = "default_context_bytes")]
    pub bytes: u32,
    #[schemars(description = "Output format: tsv (default), csv, json, or verbose.")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fmt: Option<String>,
    #[schemars(
        description = "Target a specific open program by name or sha256 instead of the active one."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
}

impl ToParams for AddressContextArgs {
    fn into_params(self) -> Params {
        let mut p = vec![
            ("address", self.address),
            ("count", self.count.to_string()),
            ("bytes", self.bytes.to_string()),
        ];
        if let Some(f) = self.fmt {
            p.push(("fmt", f));
        }
        if let Some(prog) = self.program {
            p.push(("program", prog));
        }
        p
    }
}

const fn default_reach_depth() -> u32 {
    6
}

const fn default_reach_max() -> u32 {
    400
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct ReachabilityArgs {
    #[schemars(description = "Function name, VA, RVA or rva:… to test for reachability.")]
    pub target: String,
    #[schemars(description = "How many caller levels to walk up (default 6, max 24).")]
    #[serde(default = "default_reach_depth")]
    pub depth: u32,
    #[schemars(description = "Max transitive callers to collect (default 400).")]
    #[serde(default = "default_reach_max")]
    pub max: u32,
    #[schemars(description = "Output format: tsv (default), csv, json, or verbose.")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fmt: Option<String>,
    #[schemars(
        description = "Target a specific open program by name or sha256 instead of the active one."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
}

impl ToParams for ReachabilityArgs {
    fn into_params(self) -> Params {
        let mut p = vec![
            ("target", self.target),
            ("depth", self.depth.to_string()),
            ("max", self.max.to_string()),
        ];
        if let Some(f) = self.fmt {
            p.push(("fmt", f));
        }
        if let Some(prog) = self.program {
            p.push(("program", prog));
        }
        p
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct NebulaShapeArgs {
    #[schemars(
        description = "Optional function VA/RVA/rva:… to identify and cross-check. Omit to get the proven shape table."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[schemars(
        description = "Optional single kind: Util::Array, Util::FixedArray, Core::Ptr, Math::point, Util::StringAtom."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[schemars(description = "Output format: tsv (default), csv, json, or verbose.")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fmt: Option<String>,
    #[schemars(
        description = "Target a specific open program by name or sha256 instead of the active one."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
}

impl ToParams for NebulaShapeArgs {
    fn into_params(self) -> Params {
        let mut p: Params = Vec::new();
        if let Some(a) = self.address.filter(|s| !s.trim().is_empty()) {
            p.push(("address", a));
        }
        if let Some(k) = self.kind.filter(|s| !s.trim().is_empty()) {
            p.push(("kind", k));
        }
        if let Some(f) = self.fmt {
            p.push(("fmt", f));
        }
        if let Some(prog) = self.program {
            p.push(("program", prog));
        }
        p
    }
}

const fn default_tls_derive_max() -> u32 {
    30
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct DeriveTlsSingletonsArgs {
    #[schemars(description = "Optional class filter, e.g. SkillManager or TemplateMgr.")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    #[schemars(
        description = "Max functions to decompile in this pass (default 30, cap 120). Page with offset to cover the rest."
    )]
    #[serde(default = "default_tls_derive_max")]
    pub max: u32,
    #[schemars(
        description = "When true, merge exact slots from this pass into the program's persisted TLS table (tls_singleton_map source=derived). Default false."
    )]
    #[serde(default)]
    pub apply: bool,
    #[serde(flatten)]
    pub page: Page,
}

impl ToParams for DeriveTlsSingletonsArgs {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        p.push(("max", self.max.to_string()));
        if self.apply {
            p.push(("apply", "1".to_string()));
        }
        if let Some(c) = self.class.filter(|s| !s.trim().is_empty()) {
            p.push(("class", c));
        }
        p
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema, Default)]
pub struct LiveProbe {
    #[schemars(
        description = "define (save a probe), run (read it), list, show, or delete. Default run."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op: Option<String>,
    #[schemars(description = "Probe name, e.g. player or inventory.")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[schemars(
        description = "op=define: chain root — an absolute live VA, or tls:0x58 / teb:0x58 after live_attach                        (see tls_singleton_map for the slots)."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    #[schemars(
        description = "op=define: comma-separated hex offsets. For each one, dereference then add:                        final = [...[[base]+off0]+off1...]+offN. The final address is not dereferenced.                        Omit for a direct read at base."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offsets: Option<String>,
    #[schemars(
        description = "op=define: field layout, one per line or separated by ';' —                        'pos: vec3 +0x34; hp: f32 +0x50; name: string[32] +0x08'.                        Types: ptr, u8/16/32/64, i8/16/32/64, f32, f64, vec3, mat3x4, string[N], bytes[N]."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[schemars(description = "op=define: free text recording how the chain was derived.")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(flatten)]
    pub page: Page,
}

impl ToParams for LiveProbe {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        for (key, value) in [
            ("op", self.op),
            ("name", self.name),
            ("base", self.base),
            ("offsets", self.offsets),
            ("schema", self.schema),
            ("note", self.note),
        ] {
            if let Some(v) = value.filter(|s| !s.trim().is_empty()) {
                p.push((key, v));
            }
        }
        p
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema, Default)]
pub struct NebulaClassGraph {
    #[schemars(
        description = "Substring filter on the class or its parent (e.g. Messaging, Game::)."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    #[schemars(
        description = "Show only this class and everything deriving from it, e.g. root=Core::RefCounted."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    #[schemars(
        description = "Address of Core::Rtti::Construct, if auto-detection picks the wrong function. \
                       Normally omit it."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ctor: Option<String>,
    #[schemars(description = "Recompute instead of reusing the cached graph.")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh: Option<bool>,
    #[serde(flatten)]
    pub page: Page,
}

impl ToParams for NebulaClassGraph {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        if let Some(f) = self.filter.filter(|s| !s.trim().is_empty()) {
            p.push(("filter", f));
        }
        if let Some(r) = self.root.filter(|s| !s.trim().is_empty()) {
            p.push(("root", r));
        }
        if let Some(c) = self.ctor.filter(|s| !s.trim().is_empty()) {
            p.push(("ctor", c));
        }
        if self.refresh == Some(true) {
            p.push(("refresh", "1".to_owned()));
        }
        p
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct CatalogFilter {
    #[schemars(description = "Optional substring filter (class, FourCC, path, attr name).")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    #[serde(flatten)]
    pub page: Page,
}

impl ToParams for CatalogFilter {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        if let Some(f) = self.filter.filter(|s| !s.trim().is_empty()) {
            p.push(("filter", f));
        }
        p
    }
}

const fn default_assert_catalog_max() -> u32 {
    40
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct AssertCatalogArgs {
    #[schemars(description = "Optional substring on assert text, field, or class.")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    #[schemars(
        description = "When true, decompile referencing functions and run prove_offset (paged by offset/max). Default false is the fast string index."
    )]
    #[serde(
        default,
        deserialize_with = "de_opt_bool",
        skip_serializing_if = "Option::is_none"
    )]
    pub prove: Option<bool>,
    #[schemars(description = "Max functions to decompile when prove=true (default 40, cap 200).")]
    #[serde(default = "default_assert_catalog_max")]
    pub max: u32,
    #[serde(flatten)]
    pub page: Page,
}

impl ToParams for AssertCatalogArgs {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        p.push(("max", self.max.to_string()));
        if let Some(f) = self.filter.filter(|s| !s.trim().is_empty()) {
            p.push(("filter", f));
        }
        if let Some(v) = self.prove {
            p.push(("prove", flag(v)));
        }
        p
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct FuncsigGraphArgs {
    #[schemars(description = "Optional namespace/class substring, e.g. Skills or Messaging.")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    #[schemars(description = "\"mermaid\" (default) or \"tsv\" (namespace table).")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fmt: Option<String>,
    #[serde(
        default,
        deserialize_with = "de_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub max: Option<u32>,
    #[serde(flatten)]
    pub page: Page,
}

impl ToParams for FuncsigGraphArgs {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        if let Some(f) = self.filter.filter(|s| !s.trim().is_empty()) {
            p.push(("filter", f));
        }
        if let Some(f) = self.fmt {
            p.push(("fmt", f));
        }
        if let Some(m) = self.max {
            p.push(("max", m.to_string()));
        }
        p
    }
}

const fn default_assert_max() -> u32 {
    200
}

const fn default_sig_max() -> u32 {
    500
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct NameFromNAssert {
    #[schemars(
        description = "Optional single function VA/interior/RVA/rva:… . Empty = batch over candidates (capped by max)."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[schemars(description = "Commit renames (default false = dry-run preview table).")]
    #[serde(default)]
    pub apply: bool,
    #[schemars(
        description = "Max candidates (default 200 for decomp path; signature path uses name_from_signatures defaults)."
    )]
    #[serde(default = "default_assert_max")]
    pub max: u32,
    #[schemars(
        description = "Naming engine: auto (default, fast signature-strings), sigs/signatures/strings (xref-only, no decompile), decompile/decomp (assert-caller decomp)."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

impl ToParams for NameFromNAssert {
    fn into_params(self) -> Params {
        let mut p = vec![
            ("apply", if self.apply { "1" } else { "0" }.to_owned()),
            ("max", self.max.to_string()),
        ];
        if let Some(a) = self.address.filter(|s| !s.trim().is_empty()) {
            p.push(("address", a));
        }
        if let Some(m) = self.mode.filter(|s| !s.trim().is_empty()) {
            p.push(("mode", m));
        }
        p
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct NameFromSignatures {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default)]
    pub apply: bool,
    #[serde(default = "default_sig_max")]
    pub max: u32,
}

impl ToParams for NameFromSignatures {
    fn into_params(self) -> Params {
        let mut p = vec![
            ("apply", if self.apply { "1" } else { "0" }.to_owned()),
            ("max", self.max.to_string()),
        ];
        if let Some(a) = self.address.filter(|s| !s.trim().is_empty()) {
            p.push(("address", a));
        }
        p
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema, Default)]
pub struct ApplyMax {
    #[serde(default)]
    pub apply: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<u32>,
}

impl ToParams for ApplyMax {
    fn into_params(self) -> Params {
        let mut p = vec![("apply", if self.apply { "1" } else { "0" }.to_owned())];
        if let Some(m) = self.max {
            p.push(("max", m.to_string()));
        }
        p
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema, Default)]
pub struct NebulaBootstrap {
    #[schemars(
        description = "start (default) launches the chain and returns a job id; status polls progress; result fetches the finished report; list shows retained jobs."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op: Option<String>,
    #[schemars(
        description = "Job id from a previous start, for op=status / op=result. Omit to use the most recent job."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job: Option<String>,
    #[schemars(
        description = "Seconds op=start blocks before handing back a job id. Default 25: a small binary finishes inline, a full client returns a job to poll."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait: Option<u32>,
    #[schemars(
        description = "Commit the renames. Default false: every step runs as a dry run and reports what it would name."
    )]
    #[serde(default)]
    pub apply: bool,
    #[schemars(
        description = "Also run the decompile fill-in for assert callers the signature-string path missed. Slow (decompiles thousands of functions); off by default."
    )]
    #[serde(default)]
    pub decompile: bool,
    #[schemars(
        description = "Cap for the signature-string step. Default 50000, which covers every candidate on dro_client (~20k)."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig_max: Option<u32>,
    #[schemars(description = "Cap for the decompile fill-in step. Default 2000.")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decompile_max: Option<u32>,
    #[schemars(description = "Cap for singleton Instance() naming. Default 2000.")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_max: Option<u32>,
    #[schemars(description = "Cap for TLS singleton derivation. Default 120.")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_max: Option<u32>,
    #[schemars(
        description = "Include each step's full row-by-row output instead of just the summary table."
    )]
    #[serde(default)]
    pub verbose: bool,
}

impl ToParams for NebulaBootstrap {
    fn into_params(self) -> Params {
        let mut p = vec![
            ("apply", if self.apply { "1" } else { "0" }.to_owned()),
            (
                "decompile",
                if self.decompile { "1" } else { "0" }.to_owned(),
            ),
            ("verbose", if self.verbose { "1" } else { "0" }.to_owned()),
        ];
        if let Some(op) = self.op {
            p.push(("op", op));
        }
        if let Some(job) = self.job {
            p.push(("job", job));
        }
        for (key, value) in [
            ("wait", self.wait),
            ("sig_max", self.sig_max),
            ("decompile_max", self.decompile_max),
            ("instance_max", self.instance_max),
            ("tls_max", self.tls_max),
        ] {
            if let Some(v) = value {
                p.push((key, v.to_string()));
            }
        }
        p
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema, Default)]
pub struct ApplyOnly {
    #[serde(default)]
    pub apply: bool,
}

impl ToParams for ApplyOnly {
    fn into_params(self) -> Params {
        vec![("apply", if self.apply { "1" } else { "0" }.to_owned())]
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema, Default)]
pub struct RaknetPacketLookup {
    #[schemars(description = "Packet id as 0x8a / 8a / 138. Omit to search by query only.")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[schemars(description = "Substring match on name/notes/handler (case-insensitive).")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
}

fn parse_packet_id(raw: &str) -> Result<u8, String> {
    let t = raw.trim();
    if t.is_empty() {
        return Err("empty id".into());
    }
    let (radix, digits) = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .or_else(|| t.strip_prefix("0h"))
        .map_or_else(
            || {
                if t.chars().any(|c| matches!(c, 'a'..='f' | 'A'..='F')) {
                    (16, t)
                } else {
                    (10, t)
                }
            },
            |h| (16, h),
        );
    u8::from_str_radix(digits, radix).map_err(|e| format!("invalid packet id '{raw}': {e}"))
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct ExportOffsets {
    #[schemars(description = "Optional name filter (substring by default; regex=true for regex).")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    #[serde(
        default,
        deserialize_with = "de_opt_bool",
        skip_serializing_if = "Option::is_none"
    )]
    pub regex: Option<bool>,
    #[schemars(
        description = "Skip auto FUN_*/thunk names (default true) — export only user/named symbols."
    )]
    #[serde(
        default,
        deserialize_with = "de_opt_bool",
        skip_serializing_if = "Option::is_none"
    )]
    pub named_only: Option<bool>,
    #[schemars(description = "\"tsv\" (default: name/rva/va) or \"cpp\" constexpr skeleton.")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(flatten)]
    pub page: Page,
}

impl ToParams for ExportOffsets {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        if let Some(f) = self.filter {
            p.push(("filter", f));
        }
        if self.regex.unwrap_or(false) {
            p.push(("regex", "1".to_string()));
        }
        if let Some(n) = self.named_only {
            p.push(("named_only", if n { "1" } else { "0" }.to_string()));
        }
        if let Some(fmt) = self.format {
            p.push(("format", fmt));
        }
        p
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct Coverage {
    #[schemars(
        description = "Which coverage operation to run (defaults to a function-level report)."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path_a: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path_b: String,
    #[serde(flatten)]
    pub page: Page,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct ProposeStruct {
    pub function_address: String,
    pub variable: String,
}

impl ToParams for ProposeStruct {
    fn into_params(self) -> Params {
        vec![
            ("function_address", self.function_address),
            ("variable", self.variable),
        ]
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct SetVariables {
    pub function_address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prototype: Option<String>,
    #[serde(
        default,
        deserialize_with = "de_opt_var_edits",
        skip_serializing_if = "Option::is_none"
    )]
    pub variables: Option<Vec<VariableEdit>>,
}

fn de_opt_var_edits<'de, D>(deserializer: D) -> Result<Option<Vec<VariableEdit>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum ListOrStr {
        List(Vec<VariableEdit>),
        Str(String),
    }
    match Option::<ListOrStr>::deserialize(deserializer)? {
        None => Ok(None),
        Some(ListOrStr::List(v)) => Ok(Some(v)),
        Some(ListOrStr::Str(s)) => {
            let t = s.trim();
            if t.is_empty() {
                return Ok(None);
            }
            serde_json::from_str(t)
                .map(Some)
                .map_err(serde::de::Error::custom)
        }
    }
}

impl ToParams for SetVariables {
    fn into_params(self) -> Params {
        let mut p = vec![("function_address", self.function_address)];
        if let Some(n) = self.new_name {
            p.push(("new_name", n));
        }
        if let Some(pr) = self.prototype {
            p.push(("prototype", pr));
        }
        if let Some(vars) = self.variables.filter(|v| !v.is_empty()) {
            p.push((
                "variables",
                serde_json::to_string(&vars).unwrap_or_else(|_| "[]".to_owned()),
            ));
        }
        p
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum NamingConvention {
    Snake,
    ScreamingSnake,
    Camel,
    Pascal,
}

impl NamingConvention {
    const fn wire(self) -> &'static str {
        match self {
            Self::Snake => "snake",
            Self::ScreamingSnake => "screaming_snake",
            Self::Camel => "camel",
            Self::Pascal => "pascal",
        }
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct ApplyNamingConvention {
    pub convention: NamingConvention,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default)]
    pub apply: bool,
}

impl ToParams for ApplyNamingConvention {
    fn into_params(self) -> Params {
        let mut p = vec![("convention", self.convention.wire().to_owned())];
        if let Some(ns) = self.namespace {
            p.push(("namespace", ns));
        }
        p.push(("apply", if self.apply { "1" } else { "0" }.to_owned()));
        p
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema, Default)]
pub struct AnalyzeProgram {
    #[serde(default)]
    pub all: bool,
}

impl ToParams for AnalyzeProgram {
    fn into_params(self) -> Params {
        vec![("all", flag(self.all))]
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct SetAnalysisOption {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}
const fn default_true() -> bool {
    true
}

impl ToParams for SetAnalysisOption {
    fn into_params(self) -> Params {
        vec![("name", self.name), ("enabled", flag(self.enabled))]
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct ApplyDataType {
    pub address: String,
    #[serde(rename = "type")]
    pub data_type: String,
    #[serde(default = "default_true")]
    pub clear: bool,
}

impl ToParams for ApplyDataType {
    fn into_params(self) -> Params {
        vec![
            ("address", self.address),
            ("type", self.data_type),
            ("clear", flag(self.clear)),
        ]
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct FunctionAddress {
    pub function_address: String,
}

impl ToParams for FunctionAddress {
    fn into_params(self) -> Params {
        vec![("function_address", self.function_address)]
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct StructField {
    #[schemars(
        description = "\"set\" (default) overwrites/inserts a field; \"delete\" replaces it with undefined space."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op: Option<String>,
    pub struct_name: String,
    pub offset: u32,
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub data_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

impl ToParams for StructField {
    fn into_params(self) -> Params {
        let mut p = vec![
            ("struct", self.struct_name),
            ("offset", self.offset.to_string()),
        ];
        if let Some(o) = self.op {
            p.push(("op", o));
        }
        if let Some(t) = self.data_type {
            p.push(("type", t));
        }
        if let Some(n) = self.name {
            p.push(("name", n));
        }
        if let Some(m) = self.mode {
            p.push(("mode", m));
        }
        p
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct Freeze {
    #[schemars(
        description = "\"on\" freezes address to hex, \"off\" unfreezes address, \"list\" shows frozen addresses."
    )]
    pub op: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub address: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hex: String,
    #[serde(flatten)]
    pub page: Page,
}

impl ToParams for Freeze {
    fn into_params(self) -> Params {
        let mut p = vec![("op", self.op)];
        if !self.address.is_empty() {
            p.push(("address", self.address));
        }
        if !self.hex.is_empty() {
            p.push(("hex", self.hex));
        }
        p.extend(self.page.into_params());
        p
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct DecodeStringsAuto {
    pub address: String,
    #[serde(default = "default_decode_length")]
    pub length: u32,
    #[serde(default = "default_min_printable")]
    pub min_printable: f64,
    #[serde(default = "default_decode_max")]
    pub max: u32,
}
const fn default_decode_length() -> u32 {
    256
}
const fn default_min_printable() -> f64 {
    0.85
}
const fn default_decode_max() -> u32 {
    10
}

impl ToParams for DecodeStringsAuto {
    fn into_params(self) -> Params {
        vec![
            ("address", self.address),
            ("length", self.length.to_string()),
            ("min_printable", self.min_printable.to_string()),
            ("max", self.max.to_string()),
        ]
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct XrefGraphArgs {
    pub address: String,
    #[serde(
        default,
        deserialize_with = "de_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub max: Option<u32>,
    #[schemars(
        description = "\"mermaid\" (default, inline graph) or \"html\" (self-contained interactive page)."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fmt: Option<String>,
}

impl ToParams for XrefGraphArgs {
    fn into_params(self) -> Params {
        let mut p = vec![("address", self.address)];
        if let Some(m) = self.max {
            p.push(("max", m.to_string()));
        }
        if let Some(f) = self.fmt {
            p.push(("fmt", f));
        }
        p
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema, Default)]
pub struct GraphMax {
    #[serde(
        default,
        deserialize_with = "de_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub max: Option<u32>,
    #[schemars(
        description = "\"symbols\" (default, Ghidra namespaces) or \"funcsig\" (Nebula C++ namespaces parsed from __cdecl signature strings)."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[schemars(description = "Optional namespace substring when source=funcsig.")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
}

impl ToParams for GraphMax {
    fn into_params(self) -> Params {
        let mut p = Params::new();
        if let Some(m) = self.max {
            p.push(("max", m.to_string()));
        }
        if let Some(s) = self.source.filter(|s| !s.trim().is_empty()) {
            p.push(("source", s));
        }
        if let Some(f) = self.filter.filter(|s| !s.trim().is_empty()) {
            p.push(("filter", f));
        }
        p
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct ProgramName {
    pub name: String,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct SearchToolsArgs {
    pub query: String,
    #[serde(
        default,
        deserialize_with = "de_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub limit: Option<u32>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct ToolName {
    pub name: String,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema, Default)]
pub struct ProbeSnippetArgs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl ToParams for ProgramName {
    fn into_params(self) -> Params {
        vec![("name", self.name)]
    }
}

const NO_QUERY: &[(); 0] = &[];

const PROBE_SNIPPETS: &[(&str, &str)] = &[
    (
        "live_helpers",
        r#"var rows = new ArrayList<String>();
Object h = new Object() {
    long ptr(long a) { Long v = Live.tryReadPtr(a); return v == null ? 0L : v & 0xffffffffL; }
    long u32(long a) { Long v = Live.tryReadUInt(a); return v == null ? 0L : v; }
    int u16(long a) { Integer v = Live.tryReadU16(a); return v == null ? 0 : v; }
    float f32(long a) { Float v = Live.tryReadFloat(a); return v == null ? Float.NaN : v; }
    String str(long a, int n) { String v = Live.tryReadString(a, n); return v == null ? "" : v; }
    String hx(long v) { return "0x" + Long.toHexString(v); }
};"#,
    ),
    (
        "walk_std_tree",
        r#"long root = 0x00000000L;
Long first = Live.tryReadPtr(root);
long node = first == null ? 0L : first & 0xffffffffL;
while (node != 0) {
    Long next = Live.tryReadPtr(node + 0x04);
    Long key = Live.tryReadUInt(node + 0x10);
    Long value = Live.tryReadPtr(node + 0x14);
    if (key != null && value != null) println("0x" + Long.toHexString(node) + "\t" + key + "\t0x" + Long.toHexString(value));
    node = next == null ? 0L : next & 0xffffffffL;
}"#,
    ),
    (
        "render_bounds",
        r#"long render = 0x00000000L;
float[] min = Live.tryReadVec3(render + 0x20);
float[] max = Live.tryReadVec3(render + 0x2c);
if (min != null && max != null) {
    println("render\t0x" + Long.toHexString(render) + "\t"
            + min[0] + "," + min[1] + "," + min[2] + "\t"
            + max[0] + "," + max[1] + "," + max[2]);
}"#,
    ),
    (
        "model_candidates",
        r#"long object = 0x00000000L;
for (long off : new long[]{0x54, 0x58, 0x5c, 0xf0, 0x104}) {
    Long p = Live.tryReadPtr(object + off);
    if (p == null || p == 0) continue;
    String s = Live.tryReadString(p, 96);
    if (s != null && !s.isBlank()) println("0x" + Long.toHexString(object + off) + "\t0x" + Long.toHexString(p) + "\t" + s);
}"#,
    ),
    (
        "skeleton_records",
        r#"long skeleton = 0x00000000L;
Long table = Live.tryReadPtr(skeleton + 0x10);
Integer count = Live.tryReadU16(skeleton + 0x08);
if (table != null && count != null) {
    for (int i = 0; i < count; i++) {
        long rec = (table & 0xffffffffL) + i * 0x20L;
        Long name = Live.tryReadPtr(rec);
        Integer parent = Live.tryReadU16(rec + 0x08);
        println(i + "\t0x" + Long.toHexString(rec) + "\t" + (parent == null ? -1 : parent)
                + "\t" + (name == null ? "" : Live.tryReadString(name & 0xffffffffL, 64)));
    }
}"#,
    ),
    (
        "tsv_rows",
        r#"var out = new StringBuilder("addr\tvtable\tname\n");
for (long object : new long[]{0x00000000L}) {
    Long vt = Live.tryReadPtr(object);
    String name = Live.tryReadString(object + 0x100, 64);
    out.append("0x").append(Long.toHexString(object)).append('\t')
            .append(vt == null ? "" : "0x" + Long.toHexString(vt)).append('\t')
            .append(name == null ? "" : name.replace('\t', ' ')).append('\n');
}
println(out.toString());"#,
    ),
];

impl GhidraServer {
    pub fn new(base: Url, timeout_secs: u64, token: Option<&str>) -> Result<Self, BridgeError> {
        Ok(Self {
            http: GhidraHttp::new(base, timeout_secs, token)?,
        })
    }

    async fn get(&self, path: &str, params: impl ToParams) -> Result<CallToolResult, ErrorData> {
        Ok(self
            .http
            .get(path, &params.into_params())
            .await
            .map_or_else(tool_fail, ok_text))
    }

    async fn get_bare(&self, path: &str) -> Result<CallToolResult, ErrorData> {
        Ok(self
            .http
            .get(path, NO_QUERY)
            .await
            .map_or_else(tool_fail, ok_text))
    }

    async fn post(&self, path: &str, params: impl ToParams) -> Result<CallToolResult, ErrorData> {
        Ok(self
            .http
            .post_form(path, &params.into_params())
            .await
            .map_or_else(tool_fail, ok_text))
    }

    async fn post_bare(&self, path: &str) -> Result<CallToolResult, ErrorData> {
        Ok(self
            .http
            .post_form(path, NO_QUERY)
            .await
            .map_or_else(tool_fail, ok_text))
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct FunctionHashArgs {
    pub address: String,
    #[schemars(
        description = "\"structural\" (default) or \"semantic\" (emulation behavioral hash)."
    )]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct FunctionSummaryArgs {
    pub address: String,
    #[schemars(description = "Append an ordered API-call-sequence section (behavioral trace).")]
    #[serde(
        default,
        deserialize_with = "de_opt_bool",
        skip_serializing_if = "Option::is_none"
    )]
    pub api_calls: Option<bool>,
    #[serde(flatten)]
    pub page: Page,
}

impl ToParams for FunctionSummaryArgs {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        p.push(("address", self.address));
        if self.api_calls.unwrap_or(false) {
            p.push(("api_calls", "1".to_string()));
        }
        p
    }
}

impl ToParams for FunctionHashArgs {
    fn into_params(self) -> Params {
        let mut p = vec![("address", self.address)];
        if let Some(m) = self.mode {
            p.push(("mode", m));
        }
        p
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct ListFunctions {
    #[serde(flatten)]
    pub page: Page,
    #[schemars(
        description = "Include the entry-point address column (true, default) or list names only (false)."
    )]
    #[serde(
        default,
        deserialize_with = "de_opt_bool",
        skip_serializing_if = "Option::is_none"
    )]
    pub with_address: Option<bool>,
    #[serde(
        default,
        deserialize_with = "de_opt_bool",
        skip_serializing_if = "Option::is_none"
    )]
    pub include_auto: Option<bool>,
}

impl ToParams for ListFunctions {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        if let Some(w) = self.with_address {
            p.push(("with_address", if w { "1" } else { "0" }.to_string()));
        }
        if self.include_auto.unwrap_or(false) {
            p.push(("include_auto", "1".to_string()));
        }
        p
    }
}

#[tool_router]
impl GhidraServer {
    #[tool(
        description = "List the Ghidra scripts (.java/.py) available on the script source directories, with each script's name and directory. Read-only discovery; this server does not execute scripts",
        annotations(read_only_hint = true)
    )]
    async fn list_scripts(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("list_scripts", p).await
    }

    #[tool(
        description = "List all namespace/class names with pagination",
        annotations(read_only_hint = true)
    )]
    async fn list_classes(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("classes", p).await
    }

    #[tool(
        description = "Decompile a function to C. target is a function name OR an address; an interior address resolves to its enclosing function, and a small value that is not a mapped VA is auto-treated as an RVA (image_base+value; force with rva:0x2d202c). clean=true strips cosmetic noise (redundant (int)/(uint)/(longlong) casts on iVar/uVar/param_/local_, decompiler WARNING comment blocks, blank lines). clean=std (or aggressive) also drops std::string SSO / throw_length_error noise so HTTP/crypto in C++ loaders is readable. offset/limit page the output by line and grep=<regex> returns only matching lines — both emit 1-based line numbers so a large function can be read in pieces instead of dumped whole. For malware, prefer function_behavior first — it recovers hidden strings without a 1500-line dump",
        annotations(read_only_hint = true)
    )]
    async fn decompile(
        &self,
        Parameters(p): Parameters<Decompile>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.target.is_empty() {
            return Err(ErrorData::invalid_params("target is required", None));
        }
        self.get("decompile", p).await
    }

    #[tool(
        description = "Rename a symbol. kind=function (default): rename the function identified by old_name OR address to new_name. kind=data: rename the data label at address. kind=variable: rename old_name to new_name within the function named by function_name",
        annotations(destructive_hint = false)
    )]
    async fn rename(&self, Parameters(p): Parameters<Rename>) -> Result<CallToolResult, ErrorData> {
        if p.new_name.is_empty() {
            return Err(ErrorData::invalid_params("new_name is required", None));
        }
        match p.kind.as_deref().unwrap_or("function") {
            "function" if p.old_name.is_none() && p.address.is_none() => Err(
                ErrorData::invalid_params("kind=function needs old_name or address", None),
            ),
            "data" if p.address.is_none() => {
                Err(ErrorData::invalid_params("kind=data needs address", None))
            }
            "variable" if p.function_name.is_none() || p.old_name.is_none() => Err(
                ErrorData::invalid_params("kind=variable needs function_name and old_name", None),
            ),
            "function" | "data" | "variable" => self.post("rename", p).await,
            _ => Err(ErrorData::invalid_params(
                "kind must be function, data, or variable",
                None,
            )),
        }
    }

    #[tool(
        description = "List all memory segments with pagination",
        annotations(read_only_hint = true)
    )]
    async fn list_segments(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("segments", p).await
    }

    #[tool(
        description = "List imported symbols with pagination. Each row includes the IAT slot VA (iat_slot) — the in-memory pointer that call sites read via call qword [iat_slot] — or blank if the import has no resolved slot",
        annotations(read_only_hint = true)
    )]
    async fn list_imports(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("imports", p).await
    }

    #[tool(
        description = "List exported functions/symbols with pagination",
        annotations(read_only_hint = true)
    )]
    async fn list_exports(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("exports", p).await
    }

    #[tool(
        description = "List all non-global namespaces with pagination",
        annotations(read_only_hint = true)
    )]
    async fn list_namespaces(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("namespaces", p).await
    }

    #[tool(
        description = "List defined data labels and their values with pagination",
        annotations(read_only_hint = true)
    )]
    async fn list_data_items(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("data", p).await
    }

    #[tool(
        description = "Search for functions whose name contains the given substring",
        annotations(read_only_hint = true)
    )]
    async fn search_functions_by_name(
        &self,
        Parameters(p): Parameters<SearchFunctions>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.query.is_empty() {
            return Err(ErrorData::invalid_params("query string is required", None));
        }
        self.get("searchFunctions", p).await
    }

    #[tool(
        description = "Get a function by its address",
        annotations(read_only_hint = true)
    )]
    async fn get_function_by_address(
        &self,
        Parameters(p): Parameters<Address>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("get_function_by_address", p).await
    }

    #[tool(
        description = "Get the address currently selected by the user",
        annotations(read_only_hint = true)
    )]
    async fn get_current_address(&self) -> Result<CallToolResult, ErrorData> {
        self.get_bare("get_current_address").await
    }

    #[tool(
        description = "Get the function currently selected by the user",
        annotations(read_only_hint = true)
    )]
    async fn get_current_function(&self) -> Result<CallToolResult, ErrorData> {
        self.get_bare("get_current_function").await
    }

    #[tool(
        description = "List functions in the program, paginated. with_address=true (default) gives a fn+addr table that excludes auto-named (FUN_*) functions unless include_auto=true; with_address=false lists every function name including auto-named (the former list_methods)",
        annotations(read_only_hint = true)
    )]
    async fn list_functions(
        &self,
        Parameters(p): Parameters<ListFunctions>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("list_functions", p).await
    }

    #[tool(
        description = "Get assembly code (address: instruction; comment) for the function at or containing address (an RVA that is not a mapped VA auto-rebases to image_base+value; force with rva:0x2d202c)",
        annotations(read_only_hint = true)
    )]
    async fn disassemble_function(
        &self,
        Parameters(p): Parameters<Address>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("disassemble_function", p).await
    }

    #[tool(
        description = "Set a comment for a given address in the function pseudocode",
        annotations(destructive_hint = false)
    )]
    async fn set_decompiler_comment(
        &self,
        Parameters(p): Parameters<AddressComment>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("set_decompiler_comment", p).await
    }

    #[tool(
        description = "Set a comment for a given address in the function disassembly",
        annotations(destructive_hint = false)
    )]
    async fn set_disassembly_comment(
        &self,
        Parameters(p): Parameters<AddressComment>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("set_disassembly_comment", p).await
    }

    #[tool(
        description = "Set a function's prototype",
        annotations(destructive_hint = false)
    )]
    async fn set_function_prototype(
        &self,
        Parameters(p): Parameters<SetPrototype>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("set_function_prototype", p).await
    }

    #[tool(
        description = "Set a local variable's type",
        annotations(destructive_hint = false)
    )]
    async fn set_local_variable_type(
        &self,
        Parameters(p): Parameters<SetLocalVarType>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("set_local_variable_type", p).await
    }

    #[tool(
        description = "References for a target that is a FUNCTION NAME or an ADDRESS (an interior address or an RVA both resolve; force an RVA with rva:0x2d202c). direction=both (default): all references TO the named function, resolving imports through the IAT (call qword [__imp_X]) so Windows imports return their real call sites, not 0. direction=to: references to the target (a named function resolves to its entry). direction=from: references from the target",
        annotations(read_only_hint = true)
    )]
    async fn xrefs(&self, Parameters(p): Parameters<Xrefs>) -> Result<CallToolResult, ErrorData> {
        if p.target.is_empty() {
            return Err(ErrorData::invalid_params("target is required", None));
        }
        match p.direction.as_deref().unwrap_or("both") {
            "to" | "from" | "both" => self.get("xrefs", p).await,
            _ => Err(ErrorData::invalid_params(
                "direction must be to, from, or both",
                None,
            )),
        }
    }

    #[tool(
        description = "Forward data-flow (taint) slice from an instruction: decompiles the containing function and follows the value(s) produced at the given address through the decompiler's p-code def-use graph, returning every instruction the value flows into. If the exact address isn't a decompiler-modeled op, snaps to the nearest modeled instruction in the function (reported in the header). Intra-procedural, def-use only (not followed through memory); capped. Use to see where a decrypted/computed value ends up",
        annotations(read_only_hint = true)
    )]
    async fn taint_forward(
        &self,
        Parameters(p): Parameters<AddressPage>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.address.is_empty() {
            return Err(ErrorData::invalid_params("address is required", None));
        }
        self.get("taint_forward", p).await
    }

    #[tool(
        description = "Backward data-flow (taint) slice from an instruction: decompiles the containing function and walks the value(s) used at the given address back through the p-code def-use graph, returning every instruction that contributes to them. If the exact address isn't a decompiler-modeled op, snaps to the nearest modeled instruction in the function (reported in the header). Intra-procedural, def-use only (not followed through memory); capped. Use to find what feeds a check/key/branch",
        annotations(read_only_hint = true)
    )]
    async fn taint_backward(
        &self,
        Parameters(p): Parameters<AddressPage>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.address.is_empty() {
            return Err(ErrorData::invalid_params("address is required", None));
        }
        self.get("taint_backward", p).await
    }

    #[tool(
        description = "Compare two functions. address_a/address_b accept full VA, interior address, bare RVA, or rva:0x… (same as decompile/xrefs). mode=structural (default): mnemonic Jaccard + call sets + size → score 0-100; address_b may be in program_b for cross-binary. mode=semantic: emulate both on fixed input vectors and score identical I/O behavior (same-program only). mode=source: side-by-side decompiled C for both (clean defaults true) — the dual-pane dump structural score alone does not give",
        annotations(read_only_hint = true)
    )]
    async fn diff_functions(
        &self,
        Parameters(p): Parameters<DiffFunctions>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.address_a.is_empty() || p.address_b.is_empty() {
            return Err(ErrorData::invalid_params(
                "address_a and address_b are required",
                None,
            ));
        }
        self.get("diff_functions", p).await
    }

    #[tool(
        description = "Whole-program structural diff (bindiff-lite): matches every function in the active program against another open program (program_b, by name/sha256) using structural shape hashes (mnemonic + operand-count sequence). Reports matched count, functions only in A, only in B, and the matched function pairs (shape_hash, name@addr in each). Use to map functions across two malware variants or builds",
        annotations(read_only_hint = true)
    )]
    async fn diff_programs(
        &self,
        Parameters(p): Parameters<DiffPrograms>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.program_b.is_empty() {
            return Err(ErrorData::invalid_params("program_b is required", None));
        }
        self.get("diff_programs", p).await
    }

    #[tool(
        description = "Copy function names from the active program onto matching functions in another open program (program_b). Matches functions by structural shape hash and, for each unambiguous 1-to-1 match where the active program's function is named and program_b's is still default-named (FUN_*), renames program_b's function. Previews by default; pass apply=true to commit. The fast way to port your analysis onto a sibling binary/variant",
        annotations(destructive_hint = true)
    )]
    async fn propagate_matches(
        &self,
        Parameters(p): Parameters<PropagateMatches>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.program_b.is_empty() {
            return Err(ErrorData::invalid_params("program_b is required", None));
        }
        self.post("propagate_matches", p).await
    }

    #[tool(
        description = "List direct callers of the function at the given address",
        annotations(read_only_hint = true)
    )]
    async fn list_callers(
        &self,
        Parameters(p): Parameters<AddressPage>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("list_callers", p).await
    }

    #[tool(
        description = "List direct callees of the function at the given address",
        annotations(read_only_hint = true)
    )]
    async fn list_callees(
        &self,
        Parameters(p): Parameters<AddressPage>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("list_callees", p).await
    }

    #[tool(
        description = "List basic blocks (CFG) of the function at the given address",
        annotations(read_only_hint = true)
    )]
    async fn basic_blocks(
        &self,
        Parameters(p): Parameters<Address>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("basic_blocks", p).await
    }

    #[tool(
        description = "Read up to 65536 bytes from program memory as hex. Format: '<addr> <len> <hex>'",
        annotations(read_only_hint = true)
    )]
    async fn read_bytes(
        &self,
        Parameters(p): Parameters<ReadBytes>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("read_bytes", p).await
    }

    #[tool(
        description = "Search the program. kind=bytes: scan memory for a hex pattern (query), '??' wildcards; for large images paginate with the cursor — pass the '# next_cursor:' address as start to resume in O(1). kind=string: DEFINED string literals whose content contains query (case-insensitive). kind=text: scan raw memory for query as a literal substring in both ASCII and UTF-16LE, emitting addr+enc — finds content ids/locale keys/asset names that were never defined as program strings. kind=signature: scan for an AOB in any dialect (IDA/x64dbg/CE token '48 8B ?? E8' or code+mask '\\x48\\x8B\\x00'/'xx?'). Paginated",
        annotations(read_only_hint = true)
    )]
    async fn search(&self, Parameters(p): Parameters<Search>) -> Result<CallToolResult, ErrorData> {
        if p.query.is_empty() {
            return Err(ErrorData::invalid_params("query is required", None));
        }
        match p.kind.as_str() {
            "bytes" | "string" | "text" | "signature" => self.get("search", p).await,
            _ => Err(ErrorData::invalid_params(
                "kind must be bytes, string, text, or signature",
                None,
            )),
        }
    }

    #[tool(
        description = "Patch program memory with raw hex bytes at the given address. Modifies Ghidra's program image only. Existing code units at the target are cleared first; pass disassemble=true to re-disassemble at the patch site afterward (opt-in; default leaves the region as raw data)"
    )]
    async fn patch_bytes(
        &self,
        Parameters(p): Parameters<PatchBytes>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("patch_bytes", p).await
    }

    #[tool(
        description = "Formatted hex dump at address (addr: hex ascii). Up to 65536 bytes",
        annotations(read_only_hint = true)
    )]
    async fn hex_dump(
        &self,
        Parameters(p): Parameters<HexDump>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("hex_dump", p).await
    }

    #[tool(
        description = "List strings referenced by code inside the function at the given address",
        annotations(read_only_hint = true)
    )]
    async fn function_string_refs(
        &self,
        Parameters(p): Parameters<AddressPage>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("function_string_refs", p).await
    }

    #[tool(
        description = "Get a single instruction at the given address with its bytes, mnemonic, and any EOL comment",
        annotations(read_only_hint = true)
    )]
    async fn instruction_at(
        &self,
        Parameters(p): Parameters<Address>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("instruction_at", p).await
    }

    #[tool(description = "NOP out a range of bytes (x86 0x90). Length 1..4096")]
    async fn nop_range(
        &self,
        Parameters(p): Parameters<NopRange>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("nop_range", p).await
    }

    #[tool(
        description = "Export the current (patched) program image to a file path. Use for saving cracked binaries"
    )]
    async fn export_binary(
        &self,
        Parameters(p): Parameters<ExportBinary>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.path.is_empty() {
            return Err(ErrorData::invalid_params("path is required", None));
        }
        self.post("export_binary", p).await
    }

    #[tool(
        description = "Write a UTF-8 artifact file under the plugin's allow-listed File IO Directory, creating parent directories. Use for TSV/JSON probe artifacts without writing ad-hoc file code inside ghidra_eval",
        annotations(destructive_hint = false)
    )]
    async fn write_artifact(
        &self,
        Parameters(p): Parameters<WriteArtifact>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.path.is_empty() {
            return Err(ErrorData::invalid_params("path is required", None));
        }
        self.post("write_artifact", p).await
    }

    #[tool(
        description = "Save changes to the Ghidra project (persists renames, comments, patches)",
        annotations(destructive_hint = false)
    )]
    async fn save_program(&self) -> Result<CallToolResult, ErrorData> {
        self.post_bare("save_program").await
    }

    #[tool(
        description = "XOR-decrypt a range in Ghidra's memory using a hex key (cycled). Clears code units, writes decrypted bytes. Length 1..1048576"
    )]
    async fn xor_decrypt(
        &self,
        Parameters(p): Parameters<XorDecrypt>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("xor_decrypt", p).await
    }

    #[tool(
        description = "Import a raw memory dump file into Ghidra at the given VA. Use for packed binaries: dump decrypted memory from x64dbg, feed back, now everything is statically visible"
    )]
    async fn import_memory_dump(
        &self,
        Parameters(p): Parameters<ImportMemoryDump>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("import_memory_dump", p).await
    }

    #[tool(
        description = "Brute-force single-byte XOR sweep across a range. Reports printable-ASCII runs with their key. Great for finding obfuscated strings",
        annotations(read_only_hint = true)
    )]
    async fn find_encoded_strings(
        &self,
        Parameters(p): Parameters<FindEncodedStrings>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("find_encoded_strings", p).await
    }

    #[tool(
        description = "Recover obfuscated strings without running the sample (FLOSS-style, static). Detects SplitMix64 keystream XOR (MortisEngine / similar: golden 0x9E3779B97F4A7C15 + two mixers), rolling XOR, and contiguous MOV-imm byte stores (GET/POST/version). Reconstructs the ciphertext from .rdata MOVAPS loads and stack immediates, decrypts, and reports algo/func/seed/plaintext. address= one function or omit for a whole-program scan. algo=auto|splitmix|rolling_xor|imm|all. apply=true writes EOL comments at the decrypt loops. Use this BEFORE decompiling a 1500-line Login — host, /api/auth/login, User-Agent come out as a table",
        annotations(read_only_hint = true)
    )]
    async fn recover_hidden_strings(
        &self,
        Parameters(p): Parameters<RecoverHiddenStrings>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("recover_hidden_strings", p).await
    }

    #[tool(
        description = "One-call license / C2 / HWID / crypto surface for a loader or client. Combines WinINet/WinHTTP/BCrypt/HWID/inject imports, defined strings (JSON keys, Authorization, X-Request-Sig, |drm-v1), and recover_hidden_strings (obfuscated host/path). Returns a kind/where/detail/value table: http_api, endpoint_path, host, json_key, http_header, crypto_marker, hwid_api, inject_api, hidden_string. The first tool to run on a paid-cheat / license-locked sample",
        annotations(read_only_hint = true)
    )]
    async fn recover_auth_surface(
        &self,
        Parameters(p): Parameters<RecoverAuthSurface>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("recover_auth_surface", p).await
    }

    #[tool(
        description = "Compact malware-oriented function card. Tags (http/auth/crypto/inject/hwid/antidebug/splitmix64), imported API sequence, defined strings, and recovered hidden strings — without dumping a 1500-line std::string decompile. Use on Login, FetchPayload, AntiDebugCheck instead of function_summary_bundle when the function is huge",
        annotations(read_only_hint = true)
    )]
    async fn function_behavior(
        &self,
        Parameters(p): Parameters<FunctionBehavior>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.address.trim().is_empty() {
            return Err(ErrorData::invalid_params("address is required", None));
        }
        self.get("function_behavior", p).await
    }

    #[tool(
        description = "One-call next-gen sample intake for malware / loaders / crackmes. Emits PE facts (timestamp, subsystem, admin manifest, PDB), unpack_assist packer score, capa-style capability list (inject/C2/crypto/anti-debug/HWID/license), and optional recover_hidden_strings when deep=true. Run this first on an unknown binary instead of ten separate tools",
        annotations(read_only_hint = true)
    )]
    async fn sample_intake(
        &self,
        Parameters(p): Parameters<SampleIntake>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("sample_intake", p).await
    }

    #[tool(
        description = "capa-style capability map from imports and defined strings: process_injection, c2_http/socket, crypto_*, anti_debug, hwid, license, persistence, privilege, keylog, dyn_api, self_mod, packet_divert. Each row is capability + confidence + evidence API/string. Use after sample_intake to see WHY a flag fired",
        annotations(read_only_hint = true)
    )]
    async fn capability_map(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("capability_map", p).await
    }

    #[tool(
        description = "Reconstruct crypto recipes per function from BCrypt/WinCrypt call order plus nearby strings (SHA256, ChainingModeGCM, HMAC, |drm-v1). kind=aes_gcm_decrypt|hmac|hash|symmetric|rng. address= one function or omit for a program scan. The tool that turns DeriveKey/DecryptGCM into a one-line recipe",
        annotations(read_only_hint = true)
    )]
    async fn recover_crypto_recipe(
        &self,
        Parameters(p): Parameters<RecoverCryptoRecipe>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("recover_crypto_recipe", p).await
    }

    #[tool(
        description = "Find license/crackme compare sites: strcmp/memcmp/lstrcmp against string literals, xrefs to subscription/serial/HWID/sessionSecret strings, and CMP/SUB with fat immediates (likely magic keys). Jump list for 'where does the check happen'",
        annotations(read_only_hint = true)
    )]
    async fn find_secret_compares(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("find_secret_compares", p).await
    }

    #[tool(
        description = "Export IOCs as a YARA rule (default) or a TSV/JSON table. Pulls hosts, /api/ paths, GUIDs, mutex names, unique defined strings, and the SplitMix64 golden constant. format=yara|tsv|json|csv. deep=true also folds in recover_hidden_strings. name= YARA rule identifier",
        annotations(read_only_hint = true)
    )]
    async fn export_yara(
        &self,
        Parameters(p): Parameters<ExportYara>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("export_yara", p).await
    }

    #[tool(
        description = "Apply a recovered keystream to a ciphertext blob in the image (does NOT run the sample). algo=splitmix (default, MortisEngine-style), rolling_xor, xor8. seed is hex (0xdeadaecb09bfb3e0). increment for rolling_xor (default 1). Returns ascii + hex. Pair with recover_hidden_strings: copy seed + blob address, decrypt a range you missed",
        annotations(read_only_hint = true)
    )]
    async fn decode_keystream(
        &self,
        Parameters(p): Parameters<DecodeKeystream>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.address.trim().is_empty() {
            return Err(ErrorData::invalid_params("address is required", None));
        }
        if p.seed.trim().is_empty() {
            return Err(ErrorData::invalid_params("seed is required", None));
        }
        self.get("decode_keystream", p).await
    }

    #[tool(
        description = "PE compile-time / overlay-adjacent facts: TimeDateStamp, subsystem (GUI/CUI), DllCharacteristics, requestedExecutionLevel (admin), PDB path, debug section. Faster than hunting the manifest XML by hand",
        annotations(read_only_hint = true)
    )]
    async fn pe_facts(&self) -> Result<CallToolResult, ErrorData> {
        self.get_bare("pe_facts").await
    }

    #[tool(
        description = "Find defined data blobs whose length matches MD5 (16), SHA-1 (20), SHA-256 (32), SHA-384/512 — typical hardcoded expected hashes in license checks. Reports algo, address, hex preview, xref count. Skip all-zero / low-entropy pads",
        annotations(read_only_hint = true)
    )]
    async fn find_hash_blobs(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("find_hash_blobs", p).await
    }

    #[tool(
        description = "Find functions that VirtualProtect/NtProtectVirtualMemory and/or WriteProcessMemory — unpacker stubs, PE wipes, hook installers, manual-map. kind=protect+write is the hottest",
        annotations(read_only_hint = true)
    )]
    async fn find_self_modify(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("find_self_modify", p).await
    }

    #[tool(
        description = "Scan executable sections for 32-bit immediates matching hashes of ~180 common Windows APIs. Instantly finds FNV-1a/djb2/CRC32-based API resolvers. algo=fnv1a|fnv1a_lower|djb2|crc32",
        annotations(read_only_hint = true)
    )]
    async fn find_api_hashes(
        &self,
        Parameters(p): Parameters<FindApiHashes>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("find_api_hashes", p).await
    }

    #[tool(
        description = "Find stack-string construction in a function (MOV byte [rsp/rbp+N], imm patterns), group contiguous offsets, XOR-sweep each group, report best decoded ASCII",
        annotations(read_only_hint = true)
    )]
    async fn find_stack_strings(
        &self,
        Parameters(p): Parameters<AddressPage>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("find_stack_strings", p).await
    }

    #[tool(
        description = "Run Ghidra's p-code emulator on a function. Executes pure arithmetic / decryption loops fully in-memory (no external debugger). skip_calls=comma-separated addrs of CALL targets to skip (e.g. external APIs). capture_addr+capture_length dumps emulator memory after halt; commit=true writes it back to Ghidra program so the decrypted bytes become statically visible"
    )]
    async fn emulate(
        &self,
        Parameters(p): Parameters<Emulate>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("emulate", p).await
    }

    #[tool(
        description = "Emulate a single function with arguments and read its return value. Sets up a fresh stack, places each comma-separated integer in args (hex or decimal) into the function's parameter storage per its calling convention, runs from the entry until it returns (a sentinel return address) or max_steps (default 200000), then reports the return register. capture_addr+capture_length optionally dumps emulator memory after it returns (e.g. an output buffer the function filled). The one-call way to run a decode/checksum/transform routine and see what it produces",
        annotations(read_only_hint = true)
    )]
    async fn emulate_function(
        &self,
        Parameters(p): Parameters<EmulateFunction>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.function_address.trim().is_empty() {
            return Err(ErrorData::invalid_params(
                "function_address is required",
                None,
            ));
        }
        self.post("emulate_function", p).await
    }

    #[tool(
        description = "FLOSS-style decoded-string recovery: emulate a suspected decoder function (optionally with args) on a fresh stack with memory-write tracking, then scan EVERY region the function wrote (stack, heap, or global — captured via the emulator's write set), plus an optional output_addr buffer, for emerging ASCII and UTF-16LE strings (min_len, default 4). Recovers strings that exist only after a decode routine runs (stackstrings, return-a-buffer, in-place, or global-buffer decoders) without you knowing where the output lands. Pure p-code emulation: no real API/syscalls, so API-dependent decoders may not complete — point output_addr at the destination buffer when known",
        annotations(read_only_hint = true)
    )]
    async fn recover_decoded_strings(
        &self,
        Parameters(p): Parameters<RecoverDecodedStrings>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.function_address.trim().is_empty() {
            return Err(ErrorData::invalid_params(
                "function_address is required",
                None,
            ));
        }
        self.post("recover_decoded_strings", p).await
    }

    #[tool(
        description = "Start a persistent p-code emulator session at an address and return an emu_id. Unlike one-shot emulate, the session keeps register/memory state alive across calls so you can interactively step, inspect, and continue. stack sets the initial stack pointer (default 0x7fff0000). Drive it with emu_session (op=step/run_to/regs/setreg/read/write/close). Idle sessions are garbage-collected after 30 minutes"
    )]
    async fn emu_start(
        &self,
        Parameters(p): Parameters<EmuStart>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.start.is_empty() {
            return Err(ErrorData::invalid_params("start is required", None));
        }
        self.post("emu_start", p).await
    }

    #[tool(
        description = "Drive a persistent emulator session (from emu_start) by emu_id. op=step: advance count instructions (default 1), stops early on halt. op=run_to: run until PC reaches stop (required) or max_steps (default 100000). op=regs: dump common registers (full=true for the whole bank). op=setreg: set register=value (0x-hex or decimal, negatives ok) to seed args/pointers. op=read: read length bytes (default 64) of emulator memory at address (reflects emulated writes). op=write: write hex bytes at address to stage input. op=close: dispose the session"
    )]
    async fn emu_session(
        &self,
        Parameters(p): Parameters<EmuSession>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.emu_id.is_empty() {
            return Err(ErrorData::invalid_params("emu_id is required", None));
        }
        match p.op.as_str() {
            "run_to" if p.stop.is_none() => Err(ErrorData::invalid_params(
                "stop is required for op=run_to",
                None,
            )),
            "setreg" if p.register.is_none() || p.value.is_none() => Err(
                ErrorData::invalid_params("register and value are required for op=setreg", None),
            ),
            "read" | "write" if p.address.is_none() => Err(ErrorData::invalid_params(
                "address is required for op=read/write",
                None,
            )),
            "write" if p.hex.is_none() => Err(ErrorData::invalid_params(
                "hex is required for op=write",
                None,
            )),
            "step" | "run_to" | "regs" | "setreg" | "read" | "write" | "close" => {
                self.post("emu_session", p).await
            }
            _ => Err(ErrorData::invalid_params(
                "op must be step, run_to, regs, setreg, read, write, or close",
                None,
            )),
        }
    }

    #[tool(
        description = "Sliding-window Shannon entropy scanner. Finds packed/encrypted/compressed regions inside any section. threshold default 7.5, window 64..8192",
        annotations(read_only_hint = true)
    )]
    async fn high_entropy_regions(
        &self,
        Parameters(p): Parameters<HighEntropyRegions>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("high_entropy_regions", p).await
    }

    #[tool(
        description = "Create a user-defined label at the given address",
        annotations(destructive_hint = false)
    )]
    async fn create_label(
        &self,
        Parameters(p): Parameters<CreateLabel>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("create_label", p).await
    }

    #[tool(
        description = "List memory sections with RWX permissions, size, and Shannon entropy (high = likely packed)",
        annotations(read_only_hint = true)
    )]
    async fn list_sections_detailed(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("sections_detailed", p).await
    }

    #[tool(
        description = "Detect packer/protector indicators: RWX high-entropy sections and known protector section names (.vlizer=Oreans Code Virtualizer, .vmp=VMProtect, .themida, UPX, ASPack, Enigma, MPRESS, NsPack). Run during intake to spot virtualized/packed binaries",
        annotations(read_only_hint = true)
    )]
    async fn detect_protector(&self) -> Result<CallToolResult, ErrorData> {
        self.get_bare("detect_protector").await
    }

    #[tool(
        description = "Map the boundary of packer/protector sections: control-flow transitions from normal code INTO the protected region (the VM/engine entry points — where virtualized functions hand off to the protector), grouped by engine target with hit counts and source functions, plus the reverse (APIs/callbacks the engine reaches back into). The single best triage for a virtualized/packed binary: shows exactly which functions were virtualized and the shared engine entry they funnel to. Run after detect_protector",
        annotations(read_only_hint = true)
    )]
    async fn analyze_virtualization(&self) -> Result<CallToolResult, ErrorData> {
        self.get_bare("analyze_virtualization").await
    }

    #[tool(
        description = "One-call obfuscation verdict for the whole program: combines protector-section detection, the VM/protector boundary (entry-site count, engine targets, count of functions that enter the protector), and high-entropy block count into a single triage summary (VIRTUALIZED/PACKED/CLEAN). The fast first-look that no single existing tool gives — run it during intake before deciding whether you need detect_protector/analyze_virtualization detail",
        annotations(read_only_hint = true)
    )]
    async fn obfuscation_profile(&self) -> Result<CallToolResult, ErrorData> {
        self.get_bare("obfuscation_profile").await
    }

    #[tool(
        description = "Decode the PE binary-hardening mitigations from the image's DllCharacteristics: ASLR (DYNAMICBASE), High-Entropy ASLR, DEP/NX, Control Flow Guard, SEH-disabled, Force Integrity, AppContainer, plus a /GS stack-cookie heuristic. The fast 'how hardened is this target' triage for exploit/security work",
        annotations(read_only_hint = true)
    )]
    async fn detect_security_mitigations(&self) -> Result<CallToolResult, ErrorData> {
        self.get_bare("detect_security_mitigations").await
    }

    #[tool(
        description = "Enumerate PE TLS callbacks — functions registered in the TLS directory's AddressOfCallBacks array that run BEFORE the entry point. A classic anti-debug / early-init / execution-hiding spot in malware and protectors. Reports each callback address and its containing function (empty list if none)",
        annotations(read_only_hint = true)
    )]
    async fn list_tls_callbacks(&self) -> Result<CallToolResult, ErrorData> {
        self.get_bare("list_tls_callbacks").await
    }

    #[tool(
        description = "Nebula3/dro TLS singleton slot map (NOT PE TLS callbacks). Baked table plus slots persisted by derive_tls_singletons apply=true (source=static|derived|conflict). TLS+0x58 ClientGameWorld, +0x5e0 SkillManager, +0x5b0 TemplateManager, +0x90 ClientActorManager, +0x300 TransformDevice, +0x6b0 EntityManager, etc. After live_attach, also resolves the game-thread TLS base and fills live pointer columns. Use with read_memory base=tls:0x90 after attach",
        annotations(read_only_hint = true)
    )]
    async fn tls_singleton_map(&self) -> Result<CallToolResult, ErrorData> {
        self.get_bare("tls_singleton_map").await
    }

    #[tool(
        description = "Recover Nebula3 Util::FixedArray / Array / Dictionary layout from a function's decompile: field name (this->foo.Size()), size_off, elems_off (typically +8), stride (from indexer). address = function VA/RVA/rva:; optional variable = base param (default param_1). Far more useful than generic propose_struct for container fields",
        annotations(read_only_hint = true)
    )]
    async fn nebula_container_layout(
        &self,
        Parameters(p): Parameters<NebulaContainerLayout>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.address.trim().is_empty() {
            return Err(ErrorData::invalid_params("address is required", None));
        }
        self.get("nebula_container_layout", p).await
    }

    #[tool(
        description = "PROVE a struct field offset from the n_assert that names it, instead of guessing. Nebula3/Drasa debug builds carry n_assert(\"this->field ...\", \"source/file.cc\", line, \"FUNCSIG\") and the offset is the register displacement in the compare that guards it. Give address=<function> to prove every offset in one function, or field=<name> and/or class=<name> to find the asserting functions program-wide by their assert strings. TSV cols: class,field,offset,width,base,container,confidence,assert,source,line,site,func,func_addr,funcsig,detail. offset is a BYTE offset (pointer arithmetic is rescaled by element size) from base; class comes from the assert's own FUNCSIG so inlined asserts are attributed to the inlined class, not the enclosing function. confidence: exact = one field and one guarded dereference; ambiguous = every candidate listed; size-member = a Size() load whose container base needs nebula_shape; no-guard/indirect = assert found but no offset provable, never silently dropped",
        annotations(read_only_hint = true)
    )]
    async fn prove_offset(
        &self,
        Parameters(p): Parameters<ProveOffsetArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let blank = |s: &Option<String>| s.as_ref().is_none_or(|v| v.trim().is_empty());
        if blank(&p.address) && blank(&p.field) && blank(&p.class) {
            return Err(ErrorData::invalid_params(
                "give address=<function> to prove every offset in one function, or field=<name> and/or class=<name> to search assert strings program-wide",
                None,
            ));
        }
        self.get("prove_offset", p).await
    }

    #[tool(
        description = "Answer definitively whether an address is a function start, and if not, where the instruction containing it actually begins. Use this BEFORE reading a byte window or judging a symbol pin: read_bytes at an interior address silently returns a shifted window and makes a clean prologue look like garbage. Emits # verdict (function_start | instruction_start | mid_instruction | data | undefined), # instruction starts/len/delta/aligned, # unshifted hex from the real instruction start, # entry_bytes hex from the containing function entry, # pdata_slot when the address is itself a RUNTIME_FUNCTION record, and # pdata_cover giving the function the exception directory says owns this address plus whether that agrees with Ghidra. Then a TSV of surrounding instructions, cols: addr,delta,bytes,text,mark",
        annotations(read_only_hint = true)
    )]
    async fn address_context(
        &self,
        Parameters(p): Parameters<AddressContextArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.address.trim().is_empty() {
            return Err(ErrorData::invalid_params("address is required", None));
        }
        self.get("address_context", p).await
    }

    #[tool(
        description = "Decide whether a function is dead or live, ignoring its own .pdata unwind entry. A lone DATA xref to a function is almost always its own RUNTIME_FUNCTION record, not a dispatch table, and mistaking one for the other is how implemented-but-never-constructed code gets called live. Classifies every reference as self_unwind (excluded), call, vtable, crt_init, data_table or pdata_other, then walks callers up to depth. Emits # verdict: unreferenced | only_via_vtable | data_only | crt_init | called. crt_init is a C++ static initializer (.CRT$XCU or atexit / Factory::Register thunk) — not dead. TSV cols: kind(ref|caller|root),addr,func,section,ref_type,depth,note",
        annotations(read_only_hint = true)
    )]
    async fn reachability(
        &self,
        Parameters(p): Parameters<ReachabilityArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.target.trim().is_empty() {
            return Err(ErrorData::invalid_params("target is required", None));
        }
        self.get("reachability", p).await
    }

    #[tool(
        description = "The proven Nebula3 container geometry, and a cross-check against real code. With no arguments returns the fixed table: Util::Array size@0x08 elems@0x10, Util::FixedArray size@0x00 elems@0x08, Core::Ptr 8 bytes with the pointee named by FUNCSIG, Math::point 16 bytes with w>0, Util::StringAtom 8-byte interned pointer, each row carrying its discriminating assert string and header. With address=<function> it identifies which container the function or its direct callees actually assert, derives size_off/elems_off from the dereferences in the guard, and sets agrees=yes|conflict|unchecked so a shape that contradicts the code is loud instead of silent. TSV cols: kind,elem_type,size_off,elems_off,width,derived_size_off,derived_elems_off,agrees,via,func,assert,source,line,funcsig",
        annotations(read_only_hint = true)
    )]
    async fn nebula_shape(
        &self,
        Parameters(p): Parameters<NebulaShapeArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("nebula_shape", p).await
    }

    #[tool(
        description = "Derive Nebula3/Drasa TLS singleton slots from the binary instead of trusting a hand-typed table. Finds every function asserting \"0 != Singleton\", reads the tls_base[slot] compare that guards it, and takes the class from the assert's FUNCSIG, so SkillManager@0x5e0 and TemplateMgr@0x5b0 fall out mechanically. Cross-checks each derived slot against the static tls_singleton_map table and marks it yes, new or conflict. apply=true merges exact slots into the program (tls_singleton_map source=derived). TSV cols: slot,class,agrees,known_type,confidence,func,func_addr,site,source,line,funcsig. Decompiles are capped by max; the header reports how many reference sites were left unscanned and the offset to resume at",
        annotations(destructive_hint = true)
    )]
    async fn derive_tls_singletons(
        &self,
        Parameters(p): Parameters<DeriveTlsSingletonsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("derive_tls_singletons", p).await
    }

    #[tool(
        description = "Catalog Nebula3 Core::Factory / Core::Rtti classes with no decompile. Walks callers of Factory::Register and Rtti::Construct, reads the class-name string, a printable FourCC imm32 (Messaging::Defend → DFND), and the BSS RTTI operand. TSV cols: class,fourcc,fourcc_ascii,rtti,register,register_addr,factory,via,thunk,thunk_addr. filter=Messaging or Skills. The real class graph for this engine — MSVC RTTI here is PathEngine only",
        annotations(read_only_hint = true)
    )]
    async fn factory_catalog(
        &self,
        Parameters(p): Parameters<CatalogFilter>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("factory_catalog", p).await
    }

    #[tool(
        description = "The Nebula3 class hierarchy AND every object size, recovered from Core::Rtti::Construct(name, fourcc, creator, parent, sizeof) — the static initialiser every __ImplementClass emits. Gives what factory_catalog cannot: the parent link (so the full inheritance chain) and sizeof(class), which bounds struct recovery so you know when a layout is complete instead of guessing. Also a superset of factory_catalog, since abstract bases have an Rtti but are never factory-registered. Cols: class,fourcc,size,parent,depth,rtti,creator. root=Core::RefCounted limits to a subtree; fmt=mermaid|dot draws the tree. No decompile — reads call-site operands, so it is fast",
        annotations(read_only_hint = true)
    )]
    async fn nebula_class_graph(
        &self,
        Parameters(p): Parameters<NebulaClassGraph>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("nebula_class_graph", p).await
    }

    #[tool(
        description = "Named, persistent live-memory reads. Working out a pointer chain and field layout is slow (pointer_scan, prove_offset); reading it afterwards should be one call. op=define saves a chain + schema under a name into the program database, so it survives restarts and travels with the .gdb; op=run resolves and reads it. Base may be an absolute live VA or tls:0x58 / teb:0x58 after live_attach (tls_singleton_map lists the slots). Offsets follow the read_pointer_path rule: deref then add, per offset. Use this instead of rebuilding a pointer path and schema by hand on every read",
        annotations(read_only_hint = false, destructive_hint = false)
    )]
    async fn live_probe(
        &self,
        Parameters(p): Parameters<LiveProbe>,
    ) -> Result<CallToolResult, ErrorData> {
        match p.op.as_deref().unwrap_or("run") {
            "define" | "set" if p.name.is_none() || p.base.is_none() || p.schema.is_none() => Err(
                ErrorData::invalid_params("op=define needs name, base, and schema", None),
            ),
            "run" | "read" | "show" | "delete" | "remove" if p.name.is_none() => {
                Err(ErrorData::invalid_params("this op needs name=", None))
            }
            "define" | "set" | "run" | "read" | "show" | "delete" | "remove" | "list" => {
                self.post("live_probe", p).await
            }
            other => Err(ErrorData::invalid_params(
                format!("op must be define, run, list, show, or delete (got {other:?})"),
                None,
            )),
        }
    }

    #[tool(
        description = "Index every n_assert that names a field (this->foo). prove=false (default) is a fast defined-string table: assert,fields,str_addr,refs,sample. prove=true decompiles referencing functions and runs the prove_offset engine (page with offset/max). filter=currState or SkillManager. This is the struct database for Nebula debug builds",
        annotations(read_only_hint = true)
    )]
    async fn assert_catalog(
        &self,
        Parameters(p): Parameters<AssertCatalogArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("assert_catalog", p).await
    }

    #[tool(
        description = "Catalog the local Messaging protocol: every Messaging::Class string (joined to factory FourCC/RTTI when the static initializer was found) plus every Properties/UI *HandleMessage* dispatcher. TSV cols: kind(message|handler),class,fourcc,fourcc_ascii,rtti,func,func_addr,refs. Local game logic is message classes; the wire opcode is still raknet 0x8b PLAYER_ACTION. Chain: Messaging::UseItem → NetworkCommandCreatorProperty_HandleUseItem",
        annotations(read_only_hint = true)
    )]
    async fn messaging_catalog(
        &self,
        Parameters(p): Parameters<CatalogFilter>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("messaging_catalog", p).await
    }

    #[tool(
        description = "Catalog Attr:: names and money_* wallets. Gold is Attr money_rc (and money_vc for premium), not a C++ field — prove_offset field=gold is empty on purpose. Walks AttributeDefinitionBase::Register caller trees plus money_* strings. TSV cols: name,kind(attr|money),str_addr,refs,func,func_addr",
        annotations(read_only_hint = true)
    )]
    async fn attr_catalog(
        &self,
        Parameters(p): Parameters<CatalogFilter>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("attr_catalog", p).await
    }

    #[tool(
        description = "Group functions by the embedded Jenkins/source path in n_assert strings (stripped at /code/, /nebula3/, /drasa_online/). TSV cols: path,dir,strings,xrefs,funcs,sample,sample_addr. filter=shared/skills or client/properties to open a whole subsystem without knowing a symbol",
        annotations(read_only_hint = true)
    )]
    async fn source_tree(
        &self,
        Parameters(p): Parameters<CatalogFilter>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("source_tree", p).await
    }

    #[tool(
        description = "Render the real Nebula C++ namespace/class graph from __cdecl/__thiscall signature strings (not Ghidra's DLL/switchD_* namespaces). fmt=mermaid (default) or tsv (ns,parent,classes,sigs). filter=Skills. namespace_graph source=funcsig is the same mermaid path",
        annotations(read_only_hint = true)
    )]
    async fn funcsig_graph(
        &self,
        Parameters(p): Parameters<FuncsigGraphArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("funcsig_graph", p).await
    }

    #[tool(
        description = "Locate Nebula3 assert/error helpers in the open program: n_assert (often two), n_error, n_warning — by symbol name and by \"NEBULA ASSERTION\" string xrefs. Returns role/name/address/caller counts. Name these helpers first if auto-named, then run name_from_n_assert",
        annotations(read_only_hint = true)
    )]
    async fn nebula_assert_helpers(&self) -> Result<CallToolResult, ErrorData> {
        self.get_bare("nebula_assert_helpers").await
    }

    #[tool(
        description = "One-screen Nebula3/DRO readiness report: function counts (auto vs named), assert-helper status, how many auto-named callers of n_assert/n_error/n_warning are ready for mass rename. Print the recommended tool sequence (name_from_n_assert → tls_singleton_map → raknet). Start here on a new client binary",
        annotations(read_only_hint = true)
    )]
    async fn nebula_engine_survey(&self) -> Result<CallToolResult, ErrorData> {
        self.get_bare("nebula_engine_survey").await
    }

    #[tool(
        description = "Run the whole Nebula3/DRO symbol-recovery chain: seed_nebula_helpers → name_from_signatures → (optional) name_from_n_assert mode=decompile → name_nebula_instances → derive_tls_singletons. Use this instead of the sequence nebula_engine_survey prints; it defaults sig_max to 50000 rather than 500, which is what a ~20k-candidate client needs. Runs as a BACKGROUND JOB because the chain takes minutes on a real client: op=start (default) waits `wait` seconds (25 by default) and, if it has not finished, returns a job id — then poll op=status job=<id> and read op=result job=<id>. Reports a per-step table (status, rows, ms) plus before/after named-function counts. Dry-run by default; apply=true commits. Each step is isolated, so one failure does not lose the others",
        annotations(destructive_hint = true)
    )]
    async fn nebula_bootstrap(
        &self,
        Parameters(p): Parameters<NebulaBootstrap>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("nebula_bootstrap", p).await
    }

    #[tool(
        description = "Auto-discover and optionally rename Nebula assert helpers (n_assert, n_assert2, n_error, n_warning) by scoring callees of __cdecl signature sites + NEBULA ASSERTION/CRITICAL strings. Dry-run default; apply=true commits helper names. Run this once on a fresh DRO client before mass naming",
        annotations(destructive_hint = true)
    )]
    async fn seed_nebula_helpers(
        &self,
        Parameters(p): Parameters<ApplyOnly>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("seed_nebula_helpers", p).await
    }

    #[tool(
        description = "Mass-name FUN_* for Nebula3/DRO. mode=auto|sigs (default path): rename from embedded __cdecl signature string xrefs — NO decompile, very fast (~15k+ on dro_client). mode=decompile: decompile callers of n_assert/n_error/n_warning and extract 4th-arg signatures. address= for one function. Dry-run default; apply=true commits + plate comments (file:line) + placeholder types. Prefer name_from_signatures for bulk; use seed_nebula_helpers first if helpers unnamed",
        annotations(destructive_hint = true)
    )]
    async fn name_from_n_assert(
        &self,
        Parameters(p): Parameters<NameFromNAssert>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("name_from_n_assert", p).await
    }

    #[tool(
        description = "Fastest Nebula symbol recovery: walk defined strings containing __cdecl/__thiscall signatures, follow xrefs, rename unique auto-named functions (Util::Array<...>::operator= → Util_Array6…9_operator). No decompile. Dry-run default; apply=true commits. max default 500. On dro_client ~15k unique auto-nameable. Use before hand-naming or decompile-based assert naming",
        annotations(destructive_hint = true)
    )]
    async fn name_from_signatures(
        &self,
        Parameters(p): Parameters<NameFromSignatures>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("name_from_signatures", p).await
    }

    #[tool(
        description = "List Nebula/DSO C++ singleton Instance() methods recovered from signature strings (…::Instance(void)), with ref counts and containing function. Read-only map of Game::EntityManager::Instance, Audio2 servers, etc.",
        annotations(read_only_hint = true)
    )]
    async fn list_nebula_instances(&self) -> Result<CallToolResult, ErrorData> {
        self.get_bare("list_nebula_instances").await
    }

    #[tool(
        description = "Rename auto-named functions that uniquely reference ::Instance(void) signature strings to Type_Instance style names. Dry-run default; apply=true commits + plate comment. Pairs with tls_singleton_map for live singleton navigation",
        annotations(destructive_hint = true)
    )]
    async fn name_nebula_instances(
        &self,
        Parameters(p): Parameters<ApplyMax>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("name_nebula_instances", p).await
    }

    #[tool(
        description = "Look up Drakensang Online / Nebula3 RakNet packet IDs without web search. id=0x8a|8a|138 and/or query=substring (name/notes/handler). Returns id/name/direction/notes/handler_hint. Covers handshake (0x05–0x13), disconnect, and DSO custom 0x82–0x8e (service identify, time sync, game state, map, client auth, player action). Pair with decompile of RakNetClient dispatch and ghidra://dro/raknet-* resources",
        annotations(read_only_hint = true)
    )]
    async fn raknet_packet_lookup(
        &self,
        Parameters(p): Parameters<RaknetPacketLookup>,
    ) -> Result<CallToolResult, ErrorData> {
        use std::fmt::Write as _;
        let id = match p.id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(raw) => {
                Some(parse_packet_id(raw).map_err(|e| ErrorData::invalid_params(e, None))?)
            }
            None => None,
        };
        let query = p.query.as_deref();
        let query_empty = query.map(str::trim).is_none_or(str::is_empty);
        if id.is_none() && query_empty {
            return Err(ErrorData::invalid_params(
                "provide id and/or query (e.g. id=0x8a or query=map)",
                None,
            ));
        }
        let rows = crate::dro::lookup(id, query);
        if rows.is_empty() {
            return Ok(ok_text(format!(
                "# no raknet packet match id={id:?} query={query:?}\n# see ghidra://dro/raknet-packet-ids"
            )));
        }
        let mut out = String::from("id\tname\tdir\tnotes\thandler\n");
        for r in rows {
            let _ = writeln!(
                out,
                "0x{:02x}\t{}\t{}\t{}\t{}",
                r.id, r.name, r.direction, r.notes, r.handler_hint
            );
        }
        Ok(ok_text(out))
    }

    #[tool(
        description = "Assemble x86/ARM/etc. assembly text to machine-code bytes at a given address (address matters for relative/RIP-relative encoding), via Ghidra's Assembler. Multiple instructions separated by newlines or ';' are assembled sequentially and the combined hex returned. Does NOT write — feed the bytes to patch_bytes to apply. The inverse of disassemble_function",
        annotations(read_only_hint = true)
    )]
    async fn assemble_code(
        &self,
        Parameters(p): Parameters<AssembleCode>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.address.trim().is_empty() || p.assembly.trim().is_empty() {
            return Err(ErrorData::invalid_params(
                "address and assembly are required",
                None,
            ));
        }
        self.get("assemble_code", p).await
    }

    #[tool(
        description = "Extract the ordered sequence of calls a function makes — a behavioral fingerprint for malware triage. Walks the function body in address order and resolves each call target; api_only (default true) keeps only imported-API calls (resolved through thunks/IAT), api_only=false includes internal calls. Pairs with function_summary_bundle",
        annotations(read_only_hint = true)
    )]
    async fn extract_api_call_sequences(
        &self,
        Parameters(p): Parameters<ApiCallSequence>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.address.trim().is_empty() {
            return Err(ErrorData::invalid_params("address is required", None));
        }
        self.get("extract_api_call_sequences", p).await
    }

    #[tool(
        description = "Parse a virtualizer dispatch/descriptor table into a function map. Reads 8-byte entries (u32 call_site_RVA, u32 bytecode_dest_RVA) at table_address until a zero entry or max_entries, resolves each call-site RVA to its absolute address + containing function, and reports the bytecode destination. For Oreans Code Virtualizer the table sits at the engine's self-located header + 0x40 (each engine call site keys on its return-address RVA). Turns the raw dispatch structure into a 'virtualized function -> runtime bytecode address' map",
        annotations(read_only_hint = true)
    )]
    async fn vm_descriptor_table(
        &self,
        Parameters(p): Parameters<VmDescriptorArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.table_address.trim().is_empty() {
            return Err(ErrorData::invalid_params("table_address is required", None));
        }
        self.get("vm_descriptor_table", p).await
    }

    #[tool(
        description = "List program entry points (main/export addresses)",
        annotations(read_only_hint = true)
    )]
    async fn list_entry_points(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("entry_points", p).await
    }

    #[tool(
        description = "Scan imports and functions for classic anti-debug / anti-tamper indicators (IsDebuggerPresent, NtQueryInformationProcess, RDTSC probes, etc.). The sites column gives each indicator's call-site count, resolved through the IAT for imports — so you can jump straight to where the check is used",
        annotations(read_only_hint = true)
    )]
    async fn find_anti_debug(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("find_anti_debug", p).await
    }

    #[tool(
        description = "Return program metadata: language id, processor, address size, endianness, compiler spec, image base, executable path, sha256, creation date",
        annotations(read_only_hint = true)
    )]
    async fn program_info(&self) -> Result<CallToolResult, ErrorData> {
        self.get_bare("program_info").await
    }

    #[tool(
        description = "Return the program's full metadata map as key/value rows (compiler, file format, analysis flags, original import details, etc.) — the complete set behind program_info",
        annotations(read_only_hint = true)
    )]
    async fn program_metadata(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("program_metadata", p).await
    }

    #[tool(
        description = "List stack frame variables for the function at the given address: name, offset, datatype, size, storage",
        annotations(read_only_hint = true)
    )]
    async fn function_stack_frame(
        &self,
        Parameters(p): Parameters<Address>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("function_stack_frame", p).await
    }

    #[tool(
        description = "Parse a C header source and install the declared types into Ghidra's DataTypeManager. Returns count of types added plus any parser messages",
        annotations(destructive_hint = false)
    )]
    async fn import_c_header(
        &self,
        Parameters(p): Parameters<ImportCHeader>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("import_c_header", p).await
    }

    #[tool(
        description = "Demangle a single mangled C++ symbol using Ghidra's demanglers. Returns the demangled signature or the original string on failure",
        annotations(read_only_hint = true)
    )]
    async fn demangle_symbol(
        &self,
        Parameters(p): Parameters<DemangleSymbol>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.mangled.is_empty() {
            return Err(ErrorData::invalid_params("mangled is required", None));
        }
        self.get("demangle_symbol", p).await
    }

    #[tool(
        description = "Iterate symbols in the program, demangle each, and rename those that resolve to readable names. Returns counts",
        annotations(destructive_hint = false)
    )]
    async fn demangle_all(&self) -> Result<CallToolResult, ErrorData> {
        self.post_bare("demangle_all").await
    }

    #[tool(
        description = "Create a new StructureDataType. fields is a JSON array of {name,type,offset?}; when offset is omitted fields are appended",
        annotations(destructive_hint = false)
    )]
    async fn create_struct(
        &self,
        Parameters(p): Parameters<CreateStruct>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.name.is_empty() {
            return Err(ErrorData::invalid_params("name is required", None));
        }
        self.post("create_struct", p).await
    }

    #[tool(
        description = "Create a new UnionDataType. fields is a JSON array of {name,type}",
        annotations(destructive_hint = false)
    )]
    async fn create_union(
        &self,
        Parameters(p): Parameters<CreateUnion>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.name.is_empty() {
            return Err(ErrorData::invalid_params("name is required", None));
        }
        self.post("create_union", p).await
    }

    #[tool(
        description = "Create a new EnumDataType. size is 1/2/4/8; values is a JSON array of {name,value} (value accepts 0x hex or decimal)",
        annotations(destructive_hint = false)
    )]
    async fn create_enum(
        &self,
        Parameters(p): Parameters<CreateEnum>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.name.is_empty() {
            return Err(ErrorData::invalid_params("name is required", None));
        }
        self.post("create_enum", p).await
    }

    #[tool(
        description = "Return raw p-code for every instruction in the function at the given address. Format: '<addr>: <opcode> <inputs> -> <output>'",
        annotations(read_only_hint = true)
    )]
    async fn pcode_function(
        &self,
        Parameters(p): Parameters<Address>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("pcode_function", p).await
    }

    #[tool(
        description = "Render a call graph rooted at the function at address, BFS to depth. format=mermaid (default, renders inline in chat) or dot (Graphviz DOT source). direction: callees (default), callers, or both. depth and max_nodes bound the size",
        annotations(read_only_hint = true)
    )]
    async fn callgraph(
        &self,
        Parameters(p): Parameters<CallgraphMermaid>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.address.is_empty() {
            return Err(ErrorData::invalid_params("address is required", None));
        }
        self.get("callgraph", p).await
    }

    #[tool(
        description = "Render a function's control-flow graph as a Mermaid flowchart: basic blocks with branch edges labelled by flow type",
        annotations(read_only_hint = true)
    )]
    async fn function_cfg(
        &self,
        Parameters(p): Parameters<Address>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.address.is_empty() {
            return Err(ErrorData::invalid_params("address is required", None));
        }
        self.get("function_cfg", p).await
    }

    #[tool(
        description = "Structural CFG metrics for the function at an address: basic block count, intra-procedural edges, cyclomatic complexity, conditional blocks (out-degree > 1), exit blocks, and back-edges (loop indicator). A quick complexity read",
        annotations(read_only_hint = true)
    )]
    async fn cfg_metrics(
        &self,
        Parameters(p): Parameters<Address>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("cfg_metrics", p).await
    }

    #[tool(
        description = "Compute the dominator tree of a function's CFG: for each basic block, the immediate dominator block (the entry block has none). Reveals which blocks gate which — useful for loop/region analysis. Paginated",
        annotations(read_only_hint = true)
    )]
    async fn dominator_tree(
        &self,
        Parameters(p): Parameters<AddressPage>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("dominator_tree", p).await
    }

    #[tool(
        description = "Render a one-hop reference graph around an address: inbound references (callers/readers) and outbound references (call/jump/data targets), edges labeled by reference type. fmt=mermaid (default) renders inline in chat; fmt=html emits a self-contained offline interactive page (pan/zoom/drag, hover edge-highlight) to save as .html and open in a browser. max caps references shown, split fairly between directions (default 40, hard cap 200)",
        annotations(read_only_hint = true)
    )]
    async fn xref_graph(
        &self,
        Parameters(p): Parameters<XrefGraphArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("xref_graph", p).await
    }

    #[tool(
        description = "Render the program's namespace/class hierarchy as a Mermaid top-down graph (parent namespace -> child). source=symbols (default) uses Ghidra namespaces (DLLs / switchD_* on dro_client). source=funcsig uses __cdecl signature strings — the real Nebula module graph (Skills, Messaging, Game, …). filter= substring when source=funcsig. max caps the namespace count (default 80, hard cap 400)",
        annotations(read_only_hint = true)
    )]
    async fn namespace_graph(
        &self,
        Parameters(p): Parameters<GraphMax>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("namespace_graph", p).await
    }

    #[tool(
        description = "Render struct relationships as a Mermaid classDiagram: fields plus composition edges between structs. filter narrows by name substring; max caps struct count",
        annotations(read_only_hint = true)
    )]
    async fn struct_diagram(
        &self,
        Parameters(p): Parameters<StructDiagramArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("struct_diagram", p).await
    }

    #[tool(
        description = "Find gaps in executable sections that contain instructions but belong to no function (likely orphan/dead code). min_size filters by byte length",
        annotations(read_only_hint = true)
    )]
    async fn find_orphan_gaps(
        &self,
        Parameters(p): Parameters<FindOrphanGaps>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("find_orphan_gaps", p).await
    }

    #[tool(
        description = "Heuristic vtable scan: scan .rdata/.data.rel.ro for runs of 3+ consecutive pointers into .text. Reports (address, size, first_func_address, count, class) — class is the RTTI class name when the vtable address carries a demangled symbol, linking raw vtables to recover_rtti_classes. Paginated via offset/limit",
        annotations(read_only_hint = true)
    )]
    async fn vtable_scan(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("vtable_scan", p).await
    }

    #[tool(
        description = "List DEFINED program strings with addresses (content ids, locale keys, and other undefined/embedded text will not appear here — use search kind=text for those). filter is case-insensitive substring by default; regex=true treats filter as a regex; xrefs=true emits one row per reference with from/function/ref_type columns",
        annotations(read_only_hint = true)
    )]
    async fn list_strings(
        &self,
        Parameters(p): Parameters<ListStrings>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("strings", p).await
    }

    #[tool(
        description = "List relocation-table entries with address, type, and symbol name. Useful for unpacking, IAT reconstruction, and understanding what the loader patches",
        annotations(read_only_hint = true)
    )]
    async fn list_relocations(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("relocations", p).await
    }

    #[tool(
        description = "List Ghidra bookmarks (analysis errors/warnings, notes, etc.) with address, type, category, and comment. A quick triage view of where analysis flagged problems or left notes",
        annotations(read_only_hint = true)
    )]
    async fn list_bookmarks(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("bookmarks", p).await
    }

    #[tool(
        description = "Get active trace name, target name, target state (RUNNING/STOPPED), PID, image base, ASLR slide",
        annotations(read_only_hint = true)
    )]
    async fn debugger_status(&self) -> Result<CallToolResult, ErrorData> {
        self.get_bare("debugger_status").await
    }

    #[tool(
        description = "List all current debug targets with id, name, and state",
        annotations(read_only_hint = true)
    )]
    async fn debugger_list_targets(&self) -> Result<CallToolResult, ErrorData> {
        self.get_bare("debugger_list_targets").await
    }

    #[tool(
        description = "List loaded modules in the active (or named) trace: name, base, size, path",
        annotations(read_only_hint = true)
    )]
    async fn debugger_list_modules(
        &self,
        Parameters(p): Parameters<DebuggerListModules>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("debugger_list_modules", p).await
    }

    #[tool(
        description = "List live target threads with tid, name, and state",
        annotations(read_only_hint = true)
    )]
    async fn debugger_threads(&self) -> Result<CallToolResult, ErrorData> {
        self.get_bare("debugger_threads").await
    }

    #[tool(
        description = "Call stack of the given thread (tid, optional) or the currently focused thread",
        annotations(read_only_hint = true)
    )]
    async fn debugger_stack_trace(
        &self,
        Parameters(p): Parameters<DebuggerThreadFilter>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("debugger_stack_trace", p).await
    }

    #[tool(
        description = "Register name/value pairs for the current frame of the given thread (optional). Shows common GP/flags/segment registers by default; pass full=true for the entire bank",
        annotations(read_only_hint = true)
    )]
    async fn debugger_registers(
        &self,
        Parameters(p): Parameters<DebuggerRegisters>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("debugger_registers", p).await
    }

    #[tool(
        description = "Read raw live process memory — exact bytes, NO dereference. Works after live_attach or dbgeng. address is absolute dynamic VA, or pseudo-base tls:0x90 / teb:0x58 (requires live_attach; game-thread TLS resolved via TEB). length is byte count",
        annotations(read_only_hint = true)
    )]
    async fn debugger_read_memory(
        &self,
        Parameters(p): Parameters<DebuggerReadMemory>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("debugger_read_memory", p).await
    }

    #[tool(
        description = "Resolve a multi-level pointer chain in the live target (CheatEngine-style); live_attach or dbgeng. base may be absolute VA or tls:0x90 / teb:0x58 (live_attach). Rule: for EACH offset deref then add: final = [...[[base]+off0]+off1...]+offN. Final is NOT further deref'd; value_len dumps *final as convenience. offsets comma-hex e.g. 0x18,0x40,-0x8",
        annotations(read_only_hint = true)
    )]
    async fn read_pointer_path(
        &self,
        Parameters(p): Parameters<ReadPointerPath>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.base.is_empty() {
            return Err(ErrorData::invalid_params("base is required", None));
        }
        self.get("read_pointer_path", p).await
    }

    #[tool(
        description = "Read a typed live memory struct at an absolute dynamic address. schema accepts lines like 'vtable: ptr +0x00', 'pos: vec3 +0x34', 'name: string[64] +0x10', 'raw: bytes[16] +0x80'. Types: ptr,u8/u16/u32/u64,i8/i16/i32/i64,f32/f64,vec3,mat3x4,string[N],bytes[N]. Works with live_attach or dbgeng trace",
        annotations(read_only_hint = true)
    )]
    async fn live_read_struct(
        &self,
        Parameters(p): Parameters<LiveReadStruct>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.address.is_empty() {
            return Err(ErrorData::invalid_params("address is required", None));
        }
        if p.schema.is_empty() {
            return Err(ErrorData::invalid_params("schema is required", None));
        }
        self.post("live_read_struct", p).await
    }

    #[tool(
        description = "Reverse pointer scan over the static program image: finds pointer-aligned words whose value lands in [target - max_offset, target], i.e. addresses that point at or just before the target. Each result is a base address + the offset that reaches target (resolve it on a live target with read_pointer_path). max_offset (default 1024, hard cap 0x4000) widens the window; limit caps results (default 100, max 1000). Bounded by a 256MB scan budget",
        annotations(read_only_hint = true)
    )]
    async fn pointer_scan(
        &self,
        Parameters(p): Parameters<PointerScanArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.target.is_empty() {
            return Err(ErrorData::invalid_params("target is required", None));
        }
        self.get("pointer_scan", p).await
    }

    #[tool(
        description = "List all logical breakpoints known to the debugger",
        annotations(read_only_hint = true)
    )]
    async fn debugger_list_breakpoints(&self) -> Result<CallToolResult, ErrorData> {
        self.get_bare("debugger_list_breakpoints").await
    }

    #[tool(
        description = "Set a breakpoint. kind: software (default), hardware, read, write, access",
        annotations(destructive_hint = false)
    )]
    async fn debugger_set_breakpoint(
        &self,
        Parameters(p): Parameters<DebuggerSetBreakpoint>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.address.is_empty() {
            return Err(ErrorData::invalid_params("address is required", None));
        }
        self.post("debugger_set_breakpoint", p).await
    }

    #[tool(description = "Remove the breakpoint at the given address")]
    async fn debugger_remove_breakpoint(
        &self,
        Parameters(p): Parameters<Address>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.address.is_empty() {
            return Err(ErrorData::invalid_params("address is required", None));
        }
        self.post("debugger_remove_breakpoint", p).await
    }

    #[tool(description = "Resume execution of the live target")]
    async fn debugger_continue(&self) -> Result<CallToolResult, ErrorData> {
        self.post_bare("debugger_continue").await
    }

    #[tool(description = "Step into the next instruction")]
    async fn debugger_step_into(&self) -> Result<CallToolResult, ErrorData> {
        self.post_bare("debugger_step_into").await
    }

    #[tool(description = "Step over the next instruction (skip call targets)")]
    async fn debugger_step_over(&self) -> Result<CallToolResult, ErrorData> {
        self.post_bare("debugger_step_over").await
    }

    #[tool(description = "Interrupt the running target (break)")]
    async fn debugger_break(&self) -> Result<CallToolResult, ErrorData> {
        self.post_bare("debugger_break").await
    }

    #[tool(
        description = "Write bytes to live target memory at a dynamic address (modify values in the running process). hex is a contiguous hex byte string; switches control to RW_TARGET so writes reach the process"
    )]
    async fn live_write_memory(
        &self,
        Parameters(p): Parameters<PatchBytes>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.address.is_empty() {
            return Err(ErrorData::invalid_params("address is required", None));
        }
        if p.hex.is_empty() {
            return Err(ErrorData::invalid_params("hex is required", None));
        }
        self.post("live_write_memory", p).await
    }

    #[tool(
        description = "Write a value to a live target register (e.g. register=RAX, value=0x1234). value accepts hex (0x...) or decimal"
    )]
    async fn live_write_register(
        &self,
        Parameters(p): Parameters<LiveWriteRegister>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.register.is_empty() {
            return Err(ErrorData::invalid_params("register is required", None));
        }
        if p.value.is_empty() {
            return Err(ErrorData::invalid_params("value is required", None));
        }
        self.post("live_write_register", p).await
    }

    #[tool(
        description = "List available debug launchers/connectors for the current program (e.g. local-dbgeng to attach by PID). Shows each offer's configName and parameter names to pass to debugger_launch",
        annotations(read_only_hint = true)
    )]
    async fn debugger_list_offers(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("debugger_list_offers", p).await
    }

    #[tool(
        description = "Return the dbgeng/python connector's own stdout/stderr (the back-end terminal tail) from the last debugger_launch. This is the REAL error when a launch hangs 'alive but idle / never began a trace' — the failure that's otherwise only visible in the Ghidra GUI Terminal. Call after a stuck launch to self-diagnose (missing python deps, dbgeng.dll not found, socket/connect-back failure, etc.)",
        annotations(read_only_hint = true)
    )]
    async fn debugger_backend_log(&self) -> Result<CallToolResult, ErrorData> {
        self.get_bare("debugger_backend_log").await
    }

    #[tool(
        description = "Start a live debug session from the MCP (no Ghidra GUI needed). offer is a configName from debugger_list_offers; args is comma-separated key=value parameter overrides (e.g. the PID for a dbgeng attach offer). Fails fast with a clear message if the target PID is higher-integrity (run Ghidra elevated) or stale, instead of hanging ~90s. For the memory plane only, prefer live_attach (connector-less, no dbgeng)"
    )]
    async fn debugger_launch(
        &self,
        Parameters(p): Parameters<DebuggerLaunch>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.offer.is_empty() {
            return Err(ErrorData::invalid_params(
                "offer is required (see debugger_list_offers)",
                None,
            ));
        }
        self.post("debugger_launch", p).await
    }

    #[tool(
        description = "Detach the debugger from the current target without killing it (releases the process; a noninvasively suspended target resumes). Use to cleanly end a session or switch attach modes"
    )]
    async fn debugger_detach(&self) -> Result<CallToolResult, ErrorData> {
        self.post_bare("debugger_detach").await
    }

    #[tool(
        description = "List running processes (Windows, OS-native, no debugger). With name=, shows every match with pid, WOW64, module count, and openability — the integrity preflight that says up front whether Ghidra must run elevated. Use to find the live PID before live_attach",
        annotations(read_only_hint = true)
    )]
    async fn live_processes(
        &self,
        Parameters(p): Parameters<LiveProcesses>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("live_processes", p).await
    }

    #[tool(
        description = "Attach to a live process by name (auto-resolves the current PID, disambiguates game vs launcher by module count) or explicit pid — with NO dbgeng/python/trace. Establishes a self-healing memory-plane session: read_memory and read_pointer_path then resolve directly via OpenProcess/ReadProcessMemory, and the PID is re-resolved automatically if the process restarts. For registers/breakpoints/stepping use debugger_launch instead"
    )]
    async fn live_attach(
        &self,
        Parameters(p): Parameters<LiveAttach>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("live_attach", p).await
    }

    #[tool(
        description = "Release the connector-less live session anchor (does not kill, suspend, or detach the process)"
    )]
    async fn live_release(&self) -> Result<CallToolResult, ErrorData> {
        self.post_bare("live_release").await
    }

    #[tool(
        description = "List loaded modules (name, base, size) of the connector-less live session, read straight from the OS — no trace required",
        annotations(read_only_hint = true)
    )]
    async fn live_modules(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("live_modules", p).await
    }

    #[tool(
        description = "List thread IDs of the connector-less live session, read straight from the OS — no trace required",
        annotations(read_only_hint = true)
    )]
    async fn live_threads(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("live_threads", p).await
    }

    #[tool(
        description = "Auto-detect the live process's main Lua 5.1 lua_State by scanning the main module image for a thread object (CommonHeader.tt == LUA_TTHREAD) whose global_State points back to it. Requires live_attach. Returns the lua_State address to pass to lua_exec (or lua_exec auto-detects it)",
        annotations(read_only_hint = true)
    )]
    async fn lua_find_state(&self) -> Result<CallToolResult, ErrorData> {
        self.get_bare("lua_find_state").await
    }

    #[tool(
        description = "Execute arbitrary Lua inside the live process's embedded Lua 5.1 VM (e.g. lua_tinker). DEFAULT (safe): installs a one-time detour on a per-frame engine tick and runs your script on the target's own thread at frame start while the VM is idle, via a shared mailbox — no extra thread, no reentrancy, no heap-lock deadlock. Hook the idle frame tick (NOT lua_pcall mid-call). Hook auto-installs on first call (threads frozen + EIP-window-checked) and is removed on live_release. state = lua_State (auto via lua_find_state if omitted); fn = dobuffer-style executor int(lua_State*, char* code, int len). Built-in defaults (hook/fn/gettop/loadbuffer/pcall/settop) are example RVAs for one common lua_tinker embedder — always override hook=/fn=/gettop=/… for other binaries. rc&0xff: 1=ok, 0=lua error; rc=-3 = target has not entered lua_pcall yet. freeze=true selects the LEGACY UNSAFE CreateRemoteThread path which crashes a running VM — do not use it",
        annotations(destructive_hint = true)
    )]
    async fn lua_exec(
        &self,
        Parameters(p): Parameters<LuaExec>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.code.is_empty() {
            return Err(ErrorData::invalid_params("code is required", None));
        }
        self.post("lua_exec", p).await
    }

    #[tool(
        description = "Execute arbitrary code inside Ghidra with the FULL Ghidra API AND full live-process access — the universal escape hatch. lang='java' (default) runs a snippet as the body of a GhidraScript.run() (all FlatProgramAPI/GhidraScript members in scope: currentProgram, getFunctionAt, createLabel, setPlateComment, decompile, etc.; println(...) for output). After live_attach, the connector-less LIVE process is in scope via static Live.* helpers: read(addr,len)/write(addr,bytes)/readInt/readU16/readUInt/readLong/readPtr/readFloat/readDouble/readVec3/readString(addr,max)/tryRead*/ptrChain(base,off...)/writeInt/writeFloat/writeBytes/regions()/pid()/pointerSize() — script ANY live logic (AOB scans, struct walks, pointer maps, conditional freezes) combining static RE with live memory. Use live_probe_snippets for reusable tolerant helper bodies. Or pass a full 'public class X extends GhidraScript {...}' for imports/helpers; lang='python' runs PyGhidra if installed. Mutations commit in a transaction; commit=false for a dry run. Compile/runtime errors are returned as text so you can self-correct"
    )]
    async fn ghidra_eval(
        &self,
        Parameters(p): Parameters<GhidraEval>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.code.is_empty() {
            return Err(ErrorData::invalid_params("code is required", None));
        }
        self.post("ghidra_eval", p).await
    }

    #[tool(
        description = "Return reusable Java ghidra_eval probe snippets for live memory work. Omit name to list snippets; pass name for code. Includes tolerant Live.tryRead* helpers, tree walking, render/model/skeleton probes, and TSV row scaffolding",
        annotations(read_only_hint = true)
    )]
    async fn live_probe_snippets(
        &self,
        Parameters(p): Parameters<ProbeSnippetArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        if let Some(name) = p.name.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            if let Some((_, code)) = PROBE_SNIPPETS.iter().find(|(n, _)| *n == name) {
                return Ok(ok_text(*code));
            }
            let names = PROBE_SNIPPETS
                .iter()
                .map(|(n, _)| *n)
                .collect::<Vec<_>>()
                .join(", ");
            return Err(ErrorData::invalid_params(
                format!("unknown snippet: {name} (available: {names})"),
                None,
            ));
        }
        let names = PROBE_SNIPPETS
            .iter()
            .map(|(name, code)| format!("{name}\t{} chars", code.len()))
            .collect::<Vec<_>>()
            .join("\n");
        Ok(ok_text(format!(
            "# available live probe snippets\nname\tsize\n{names}"
        )))
    }

    #[tool(
        description = "Record a persistent analysis note on the current program — your cross-session memory of what you've learned. With address=, it becomes a Ghidra Note bookmark anchored at that address (visible in the Bookmarks window); without, a program-level note. category groups related notes (default 'MCP'). Notes persist with the program (saved on Ghidra save). Use to remember offsets, struct layouts, 'this is the FPS cap', etc., so the next session starts where this one left off"
    )]
    async fn analysis_note(
        &self,
        Parameters(p): Parameters<AnalysisNote>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.text.is_empty() {
            return Err(ErrorData::invalid_params("text is required", None));
        }
        self.post("analysis_note", p).await
    }

    #[tool(
        description = "List all persistent analysis notes recorded on the current program (both address-anchored Note bookmarks and program-level notes) — recall what was learned about this binary in prior sessions",
        annotations(read_only_hint = true)
    )]
    async fn analysis_notes(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("analysis_notes", p).await
    }

    #[tool(
        description = "Refine a function's decompilation by committing the decompiler's own inferred prototype and local variable names back into the program, then re-decompiling to verify it improved. Measures decompiler 'noise' (undefined types, casts, compiler-artifact vars) before and after; KEEPS the change only if noise did not increase, otherwise auto-REVERTS (Sidekick-style retype→re-decompile→diff→guard loop). commit=false for a dry run. Use to clean up FUN_* pseudocode before reading or renaming"
    )]
    async fn refine_function(
        &self,
        Parameters(p): Parameters<RefineFunction>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.address.is_empty() {
            return Err(ErrorData::invalid_params("address is required", None));
        }
        self.post("refine_function", p).await
    }

    #[tool(
        description = "Freeze/unfreeze live memory values, CheatEngine-style. op=on: hold address at hex bytes, re-written ~4x/sec; op=off: stop freezing address; op=list: show currently frozen addresses and the values held"
    )]
    async fn freeze(&self, Parameters(p): Parameters<Freeze>) -> Result<CallToolResult, ErrorData> {
        match p.op.as_str() {
            "on" if p.address.is_empty() || p.hex.is_empty() => Err(ErrorData::invalid_params(
                "address and hex are required for op=on",
                None,
            )),
            "off" if p.address.is_empty() => Err(ErrorData::invalid_params(
                "address is required for op=off",
                None,
            )),
            "on" | "off" | "list" => self.post("freeze", p).await,
            _ => Err(ErrorData::invalid_params(
                "op must be on, off, or list",
                None,
            )),
        }
    }

    #[tool(
        description = "CheatEngine-style live-memory value scan with a session lifecycle. op=first: start a scan for value — type i8|i16|i32|i64|f32|f64|string|bytes (default i32); skips loaded modules unless all=true (slower) and exclude_modules forces skipping; tolerance (f32/f64) matches within +/- of target; max_mb raises the budget (default 1024, cap 8192); returns a scan_id immediately (async — poll op=results for status). op=next: refine scan_id by re-reading memory, comparator exact|changed|unchanged|increased|decreased (exact needs value). op=results: list remaining candidates with dynamic+static addresses and current values (limit caps rows). op=close: free the session"
    )]
    async fn scan(&self, Parameters(p): Parameters<Scan>) -> Result<CallToolResult, ErrorData> {
        match p.op.as_str() {
            "first" if p.value.as_deref().unwrap_or("").is_empty() => Err(
                ErrorData::invalid_params("value is required for op=first", None),
            ),
            "next" | "results" | "close" if p.scan_id.is_empty() => {
                Err(ErrorData::invalid_params("scan_id is required", None))
            }
            "first" | "next" | "results" | "close" => self.post("scan", p).await,
            _ => Err(ErrorData::invalid_params(
                "op must be first, next, results, or close",
                None,
            )),
        }
    }

    #[tool(
        description = "Translate a static program address to its live (ASLR-slid) target address",
        annotations(read_only_hint = true)
    )]
    async fn debugger_translate_static_to_dynamic(
        &self,
        Parameters(p): Parameters<Address>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("debugger_translate_static_to_dynamic", p).await
    }

    #[tool(
        description = "Translate a live target address back to its static program address",
        annotations(read_only_hint = true)
    )]
    async fn debugger_translate_dynamic_to_static(
        &self,
        Parameters(p): Parameters<Address>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("debugger_translate_dynamic_to_static", p).await
    }

    #[tool(
        description = "Locate crackme-style check functions by correlating references to success words (correct, granted, winner, flag{, congrat) with fail words (wrong, denied, invalid, try again). Functions that reference both sides are ranked by combined reference count",
        annotations(read_only_hint = true)
    )]
    async fn find_check_function(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("find_check_function", p).await
    }

    #[tool(
        description = "Extract comparison constraints from a function. Pairs each CMP/TEST/SUB with its following conditional branch and emits lhs, operator, rhs, taken-target. Register-only compares report with an empty rhs",
        annotations(read_only_hint = true)
    )]
    async fn extract_constraints(
        &self,
        Parameters(p): Parameters<Address>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("extract_constraints", p).await
    }

    #[tool(
        description = "Simplify the arithmetic/bitwise expression computed at an instruction address by recovering its linear mixed-boolean-arithmetic (MBA) normal form from high P-Code. Point at an INT_ADD/SUB/MULT/AND/OR/XOR/NEGATE site; reports the original and simplified expression plus the variable mapping. Reduces obfuscated identities like (x^y)+2*(x&y) to x+y. Guarded by an equivalence check (declines non-linear / >4-variable expressions rather than risk a wrong result)",
        annotations(read_only_hint = true)
    )]
    async fn simplify_expression(
        &self,
        Parameters(p): Parameters<Address>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.address.trim().is_empty() {
            return Err(ErrorData::invalid_params("address is required", None));
        }
        self.get("simplify_expression", p).await
    }

    #[tool(
        description = "Scan a function for opaque predicates: conditional branches whose condition is provably always-true or always-false regardless of input (a common obfuscation that inflates the CFG with dead edges). Extracts each CBRANCH condition from high P-Code into a predicate IR and classifies it by exhaustive probe evaluation. Reports each opaque branch with its verdict (ALWAYS_TRUE/ALWAYS_FALSE) and the recovered predicate. address is any instruction in the target function",
        annotations(read_only_hint = true)
    )]
    async fn find_opaque_predicates(
        &self,
        Parameters(p): Parameters<Address>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.address.trim().is_empty() {
            return Err(ErrorData::invalid_params("address is required", None));
        }
        self.get("find_opaque_predicates", p).await
    }

    #[tool(
        description = "Scan executable memory for magic-constant immediate operands used in CMP/MOV/ADD/SUB/XOR/AND/OR/IMUL/TEST/LEA/SHL/SHR/SAR/ROL/ROR/PUSH. Filters small integers (0..4, 8, 16, ...) and full-ones masks. The meaning column classifies recognized constants — float sign/abs masks, unsigned-division reciprocals (udiv-by-N), crypto inits (SHA/MD5/CRC), hash seeds (FNV, golden ratio), and debug-fill markers. Optional min/max (hex via 0x) narrow the range",
        annotations(read_only_hint = true)
    )]
    async fn find_magic_constants(
        &self,
        Parameters(p): Parameters<MagicConstantsRange>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("find_magic_constants", p).await
    }

    #[tool(
        description = "Patch known anti-debug CALL sites so the call returns 0 (BOOL FALSE). Uses the real instruction length (5 for E8 rel32, 6 for FF 15 rip+disp32), writes NOPs across the whole slot, then overwrites the first two bytes with 31 C0 (XOR EAX, EAX). dry_run by default; pass apply=true to actually patch"
    )]
    async fn neutralize_anti_debug(
        &self,
        Parameters(p): Parameters<NeutralizeAntiDebug>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("neutralize_anti_debug", p).await
    }

    #[tool(
        description = "Detect arithmetic idioms in a function: unsigned divide-by-constant magic (reciprocal form for divisors 3..255), MOVSXD sign-extend-drop, and the modulo idiom x - k*(x/k) = x %% k in both compiled forms (IMUL +k; SUB and IMUL -k; ADD). With apply=true, the match is written as an EOL comment on the instruction",
        annotations(destructive_hint = false)
    )]
    async fn idiom_simplifier(
        &self,
        Parameters(p): Parameters<IdiomSimplifierInput>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("idiom_simplifier", p).await
    }

    #[tool(
        description = "Signature/fingerprint for the code at an address. mode=bytes (default): a unique wildcarded byte AOB — walks instructions, keeps opcode/modrm, wildcards address/relative/RIP operands, extends until globally unique AND >= min_len bytes (default 8, avoids fragile sigs), trims trailing wildcards; format=ida ('48 8B ?? E8') or code ('\\x48\\x8B\\x00' + mask). mode=semantic: a BEHAVIORAL fingerprint — emulates the function over fixed input vectors with memory-write tracking and hashes its observable effects (return value, bytes written, halt reason), giving an identity robust to instruction substitution / recompilation that a byte AOB can't match",
        annotations(read_only_hint = true)
    )]
    async fn make_signature(
        &self,
        Parameters(p): Parameters<MakeSignature>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.address.is_empty() {
            return Err(ErrorData::invalid_params("address is required", None));
        }
        self.get("make_signature", p).await
    }

    #[tool(
        description = "Resolve the target(s) of relative or RIP-relative operands at an address: call rel32, jmp, conditional jumps, and lea/mov [rip+disp]. Returns operand index, reference type, resolved target address, and the symbol at the target. Use to walk a call site to the callee or a RIP-relative load to its data",
        annotations(read_only_hint = true)
    )]
    async fn resolve_relative(
        &self,
        Parameters(p): Parameters<Address>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("resolve_relative", p).await
    }

    #[tool(
        description = "Rename many symbols in one call and one transaction. items is a JSON array of {address, new_name}; renames the function at each address, else the primary symbol, else creates a label. Returns a per-item ok/fail report. Use instead of N rename calls",
        annotations(destructive_hint = false)
    )]
    async fn batch_rename(
        &self,
        Parameters(p): Parameters<BatchItems>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.items.is_empty() {
            return Err(ErrorData::invalid_params("items is required", None));
        }
        self.post("batch_rename", p).await
    }

    #[tool(
        description = "Set many comments in one call and one transaction. items is a JSON array of {address, comment, kind?} with kind=eol (default, disassembly) or pre (decompiler). Returns a per-item ok/fail report",
        annotations(destructive_hint = false)
    )]
    async fn batch_set_comment(
        &self,
        Parameters(p): Parameters<BatchItems>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.items.is_empty() {
            return Err(ErrorData::invalid_params("items is required", None));
        }
        self.post("batch_set_comment", p).await
    }

    #[tool(
        description = "One-call context pack for a function at an address: metadata + signature, cleaned decompiled C, callers, callees, and referenced strings, in one response. The fastest way to load everything needed to understand and name a function. limit caps each list section. api_calls=true appends an ordered API-call-sequence section (behavioral trace)",
        annotations(read_only_hint = true)
    )]
    async fn function_summary_bundle(
        &self,
        Parameters(p): Parameters<FunctionSummaryArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.address.is_empty() {
            return Err(ErrorData::invalid_params("address is required", None));
        }
        self.get("function_summary", p).await
    }

    #[tool(
        description = "Compact constructor/class-mapping view for a function: extracts decompiler assignments to this/param_N fields, flags vtable-looking writes, and includes referenced strings. Use when function_summary_bundle is too large",
        annotations(read_only_hint = true)
    )]
    async fn function_field_writes(
        &self,
        Parameters(p): Parameters<AddressPage>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("function_field_writes", p).await
    }

    #[tool(
        description = "Set many function prototypes in one call and one transaction. Best-effort: each item is independent, and a failing item is reported but does not roll back the successful ones. items is a JSON array of {function_address, prototype} where prototype is a full C signature. Returns a per-item ok/fail report. Use instead of N set_function_prototype calls",
        annotations(destructive_hint = false)
    )]
    async fn batch_set_prototype(
        &self,
        Parameters(p): Parameters<BatchItems>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.items.is_empty() {
            return Err(ErrorData::invalid_params("items is required", None));
        }
        self.post("batch_set_prototype", p).await
    }

    #[tool(
        description = "Retype many local variables in one call and one transaction. Best-effort: a failing item is reported but does not roll back the successful ones. items is a JSON array of {function_address, variable_name, new_type}; variable_name must match the decompiler name. Returns a per-item ok/fail report",
        annotations(destructive_hint = false)
    )]
    async fn batch_set_variable_type(
        &self,
        Parameters(p): Parameters<BatchItems>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.items.is_empty() {
            return Err(ErrorData::invalid_params("items is required", None));
        }
        self.post("batch_set_variable_type", p).await
    }

    #[tool(
        description = "Score how documented the function at an address is (0-100) with a breakdown: real name, user prototype, named params, comment, named locals. Use to decide if a function still needs work",
        annotations(read_only_hint = true)
    )]
    async fn function_completeness(
        &self,
        Parameters(p): Parameters<Address>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("function_completeness", p).await
    }

    #[tool(
        description = "List functions ranked by how little they are documented (lowest completeness score first), as a work queue for a labeling pass. Skips thunks and externals. Paginate with offset/limit to walk the worst first",
        annotations(read_only_hint = true)
    )]
    async fn find_undocumented(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("find_undocumented", p).await
    }

    #[tool(
        description = "Scan program memory for well-known cryptographic constants and report each hit's address and algorithm: AES S-box / inverse S-box / Te0 table, SHA-256 init + round constants, MD5 round constants, the MD5/SHA-1 init vector, and the CRC-32 table. Word tables are matched in the target's byte order. Fast way to spot crypto in malware or packed code",
        annotations(read_only_hint = true)
    )]
    async fn find_crypto_constants(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("find_crypto_constants", p).await
    }

    #[tool(
        description = "Extract indicators of compromise: URLs, /api/ paths, Authorization: Bearer, JWTs, IPv4, emails, registry keys, Windows/UNC paths, GUIDs, BTC wallets. scope=defined (default, Ghidra string table), raw (scan .rdata/.data as ASCII+UTF-16LE — finds hosts that were never defined as strings), or both. Use scope=both on obfuscated loaders where the C2 is XOR'd in .rdata",
        annotations(read_only_hint = true)
    )]
    async fn extract_iocs(
        &self,
        Parameters(p): Parameters<ExtractIocs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("extract_iocs", p).await
    }

    #[tool(
        description = "Find ROP gadgets in executable memory: byte-scans for ret (c3/c2) and builds short linear instruction sequences ending in ret (via Ghidra's pseudo-disassembler, so unaligned gadgets are found too). filter is a case-insensitive substring over the gadget text (e.g. 'pop rdi', 'mov rsp'); max_instrs caps gadget length (default 5). For exploit/ROP-chain work",
        annotations(read_only_hint = true)
    )]
    async fn find_rop_gadgets(
        &self,
        Parameters(p): Parameters<FindRopGadgets>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("find_rop_gadgets", p).await
    }

    #[tool(
        description = "Find potential format-string vulnerabilities (CWE-134): call sites to printf/sprintf/fprintf/snprintf/syslog/scanf-family functions whose format-string argument is NOT a constant string literal (i.e. attacker- or variable-controlled). Resolves the callee through thunks/IAT and checks whether the format-arg register is loaded by a LEA of a defined string just before the call",
        annotations(read_only_hint = true)
    )]
    async fn find_format_string_vulns(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("find_format_string_vulns", p).await
    }

    #[tool(
        description = "Find direct syscall stubs in code: syscall (x64), sysenter, and int 0x2e instructions, each verified against the disassembly. Reports the address, kind, and the syscall number (SSN) when a preceding 'mov eax, imm' is found. Surfaces Hell's-Gate-style EDR-evasion and direct-syscall malware",
        annotations(read_only_hint = true)
    )]
    async fn find_syscalls(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("find_syscalls", p).await
    }

    #[tool(
        description = "Scan defined strings for anti-VM / anti-sandbox artifacts (VMware, VirtualBox, QEMU, Xen, Hyper-V, Sandboxie driver/device names and known hypervisor MAC prefixes). Reports each string's address, category, and value. Complements find_anti_debug for sandbox-evasion triage",
        annotations(read_only_hint = true)
    )]
    async fn find_anti_vm(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("find_anti_vm", p).await
    }

    #[tool(
        description = "Score how likely the function at an address is control-flow obfuscated (0-100) from intra-procedural CFG metrics: block count, edges, cyclomatic complexity, the max in-degree (a high-in-degree hub suggests control-flow flattening), and a likely_flattened flag. Use to spot obfuscated/protected code",
        annotations(read_only_hint = true)
    )]
    async fn cfg_obfuscation_score(
        &self,
        Parameters(p): Parameters<Address>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("cfg_obfuscation_score", p).await
    }

    #[tool(
        description = "Triage whether the loaded program is packed/protected and which packer. Combines heuristics into a 0-100 score with a per-indicator breakdown: known packer section names (UPX/ASPack/VMProtect/Themida/...), high-entropy executable sections, writable+executable (RWX) sections, an unusually small import count, and an entry point sitting in a writable section. Returns score, verdict (likely/possibly/unlikely_packed), and the matched packer if any",
        annotations(read_only_hint = true)
    )]
    async fn unpack_assist(&self) -> Result<CallToolResult, ErrorData> {
        self.get_bare("unpack_assist").await
    }

    #[tool(
        description = "Map execution-coverage file(s) to the program. Files list executed addresses (one hex address/line; '0x' optional, trailing fields like hit counts ignored, '#'/';' comments skipped) under the allow-listed File IO Directory. op=report (default): path → covered/total functions + pct + covered list (which code a trace exercised). op=from_trace: path → per-function basic-block coverage (blocks_covered/blocks_total + pct, finer-grained — how deeply each function ran). op=diff: path_a vs path_b → functions only-in-A, only-in-B, and shared (what a new input reached that another didn't)",
        annotations(read_only_hint = true)
    )]
    async fn coverage(
        &self,
        Parameters(p): Parameters<Coverage>,
    ) -> Result<CallToolResult, ErrorData> {
        match p.op.as_deref().unwrap_or("report") {
            "diff" if p.path_a.is_empty() || p.path_b.is_empty() => Err(ErrorData::invalid_params(
                "path_a and path_b are required for op=diff",
                None,
            )),
            "report" | "from_trace" if p.path.is_empty() => {
                Err(ErrorData::invalid_params("path is required", None))
            }
            "report" | "from_trace" | "diff" => self.get("coverage", p).await,
            _ => Err(ErrorData::invalid_params(
                "op must be report, from_trace, or diff",
                None,
            )),
        }
    }

    #[tool(
        description = "Brute-force decode an encoded blob at an address: tries single-byte XOR, ADD, and SUB with every key (1-255) and returns the candidates whose output is mostly printable, ranked by printable ratio with a preview. Use to recover obfuscated strings once you've located the blob. length caps the bytes read; min_printable (0-1) and max tune the results",
        annotations(read_only_hint = true)
    )]
    async fn decode_strings_auto(
        &self,
        Parameters(p): Parameters<DecodeStringsAuto>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("decode_strings_auto", p).await
    }

    #[tool(
        description = "Hash/fingerprint the function at an address. mode=structural (default): address- and immediate-independent mnemonic_hash (opcodes) + shape_hash (opcodes + operand count), hashed over the body in order — an exact-match fingerprint for deduping identical functions and matching across builds with stable layout. mode=semantic: a behavioral fingerprint — emulates the function over fixed input vectors and hashes its observable effects (return + bytes written + halt), robust to instruction substitution / recompilation where the structural hash differs",
        annotations(read_only_hint = true)
    )]
    async fn function_hash(
        &self,
        Parameters(p): Parameters<FunctionHashArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.address.is_empty() {
            return Err(ErrorData::invalid_params("address is required", None));
        }
        self.get("function_hash", p).await
    }

    #[tool(
        description = "List recovered C++ classes with each class's vftable address and method count, from Ghidra's class namespaces (populated by RTTI analysis / demangling). Vtable-backed classes are listed first, ordered by method count, so real classes surface ahead of lambda/empty namespaces. Run analyze_program with RTTI enabled first to populate them. Paginated",
        annotations(read_only_hint = true)
    )]
    async fn recover_rtti_classes(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("recover_rtti_classes", p).await
    }

    #[tool(
        description = "Find call sites of runtime API-resolution functions (GetProcAddress, LoadLibrary*, GetModuleHandle*, Ldr*, dlopen/dlsym). Reports each site, its calling function, the resolver, and the api column — the resolved name string recovered from the LEA of the name argument (RDX for GetProcAddress, RCX for LoadLibrary/GetModuleHandle) when statically present. Surfaces where and what a program resolves dynamically (a common malware/evasion pattern). Pairs with find_api_hashes",
        annotations(read_only_hint = true)
    )]
    async fn find_dynamic_api_resolution(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("find_dynamic_api_resolution", p).await
    }

    #[tool(
        description = "List the data-type archives/managers available to the program (program, built-in, and any loaded GDT/file archives), with each one's name, archive type, and data-type count. Shows which type libraries are available to apply",
        annotations(read_only_hint = true)
    )]
    async fn list_data_type_archives(&self) -> Result<CallToolResult, ErrorData> {
        self.get_bare("list_data_type_archives").await
    }

    #[tool(
        description = "Apply a Ghidra data-type archive (.gdt) to the current program: opens the archive from disk and merges all its data types into the program's type manager (conflicts resolved with Ghidra's default handler, which may modify existing types), making library/SDK structs and typedefs available to apply. The path must resolve under the allow-listed File IO Directory (Tool Options), which is disabled by default",
        annotations(destructive_hint = true)
    )]
    async fn apply_gdt(
        &self,
        Parameters(p): Parameters<ApplyGdt>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.path.is_empty() {
            return Err(ErrorData::invalid_params("path is required", None));
        }
        self.post("apply_gdt", p).await
    }

    #[tool(
        description = "Run Ghidra's DWARF analyzer on the current program to recover types, function signatures, parameter names, and variables from embedded DWARF debug info (ELF/PE built with debug symbols). On-demand alternative to a full re-analysis; reports if the program has no applicable DWARF data. Mutates the program database",
        annotations(destructive_hint = true)
    )]
    async fn import_dwarf(&self) -> Result<CallToolResult, ErrorData> {
        self.post_bare("import_dwarf").await
    }

    #[tool(
        description = "Run Ghidra's PDB analyzer to load Microsoft PDB debug symbols and apply recovered names, function signatures, and types (for PE/COFF binaries with a matching .pdb found alongside the binary or on the configured symbol search path). Honors the program's analysis options; reports if PDB is disabled or matches nothing. Mutates the program database",
        annotations(destructive_hint = true)
    )]
    async fn import_pdb(&self) -> Result<CallToolResult, ErrorData> {
        self.post_bare("import_pdb").await
    }

    #[tool(
        description = "Run Ghidra's Function ID analyzer to match the program's functions against the active FID databases and apply recovered library/runtime function names (e.g. statically-linked libc/MSVCRT routines). Honors the program's analysis options; reports if FID is disabled or matches nothing. Mutates the program database",
        annotations(destructive_hint = true)
    )]
    async fn apply_fid_signatures(&self) -> Result<CallToolResult, ErrorData> {
        self.post_bare("apply_fid_signatures").await
    }

    #[tool(
        description = "Infer a struct layout from how a pointer variable is used. function_address accepts full VA, interior address, bare RVA, or rva:0x… (same resolve path as decompile). Decompiles the function, follows every load/store through the named pointer variable (parameter or local), AND captures base+const sub-pointers (&ptr->field) passed into helpers — adding them as ref_arg fields. Creates a new struct type from accessed offsets/sizes/types. Returns offset/length/type/field table",
        annotations(destructive_hint = true)
    )]
    async fn propose_struct_from_accesses(
        &self,
        Parameters(p): Parameters<ProposeStruct>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.function_address.trim().is_empty() {
            return Err(ErrorData::invalid_params(
                "function_address is required",
                None,
            ));
        }
        if p.variable.trim().is_empty() {
            return Err(ErrorData::invalid_params("variable is required", None));
        }
        self.post("propose_struct_from_accesses", p).await
    }

    #[tool(
        description = "List all programs currently open in this Ghidra tool, with name, which is active, sha256, and path. Cross-binary work (diffing, matching) needs two programs open here",
        annotations(read_only_hint = true)
    )]
    async fn list_open_programs(&self) -> Result<CallToolResult, ErrorData> {
        self.get_bare("list_open_programs").await
    }

    #[tool(
        description = "Switch the active program (the one all other tools operate on) to an open program by name or sha256. Use with list_open_programs to move between binaries",
        annotations(destructive_hint = false)
    )]
    async fn select_program(
        &self,
        Parameters(p): Parameters<ProgramName>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.name.is_empty() {
            return Err(ErrorData::invalid_params("name is required", None));
        }
        self.post("select_program", p).await
    }

    #[tool(
        description = "Atomically edit one function in a single transaction and one decompile: optionally rename it (new_name), set its prototype (full C signature), and rename/retype any of its locals or params (variables array of {variable_name, new_name?, new_type?}; new_type omitted = rename only, new_name omitted = retype only). All-or-nothing: if any field fails the whole edit is rolled back and an error with the per-field report is returned. The one-call way to fully annotate a function",
        annotations(destructive_hint = false)
    )]
    async fn set_variables(
        &self,
        Parameters(p): Parameters<SetVariables>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("set_variables", p).await
    }

    #[tool(
        description = "Batch-normalize function names to a case convention: snake, screaming_snake, camel, or pascal. Tokenizes each existing name (splitting on separators and camelCase/acronym boundaries) and rewrites it in the chosen style. Previews by default (dry-run); pass apply=true to commit the renames in one transaction. Optional namespace filter (simple name or full path). Auto-named functions (FUN_*) are skipped. Returns an address/old/new table",
        annotations(destructive_hint = true)
    )]
    async fn apply_naming_convention(
        &self,
        Parameters(p): Parameters<ApplyNamingConvention>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("apply_naming_convention", p).await
    }

    #[tool(
        description = "Locate functions by a string they reference: finds the string, follows xrefs to the containing function, emits name/entry/xref/signature. Only DEFINED program strings — use search kind=text for embedded text. regex=true for case-insensitive families like Daily|Reshuffle|Timed. max default 20. callers=true adds one-level callers (callers + caller_n columns) — string → function → callers in one call. format=ida|code",
        annotations(read_only_hint = true)
    )]
    async fn find_function_by_string(
        &self,
        Parameters(p): Parameters<FindFunctionByString>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.value.is_empty() {
            return Err(ErrorData::invalid_params("value is required", None));
        }
        self.get("find_function_by_string", p).await
    }

    #[tool(
        description = "Export a shade-style offsets skeleton: named functions as name + RVA (+ VA). named_only=true (default) skips FUN_* auto names. filter=substring or regex=true. format=tsv (default) or cpp (constexpr std::uint32_t Name = 0xrva;). Paginate with offset/limit. Use after labeling to dump a client offsets list",
        annotations(read_only_hint = true)
    )]
    async fn export_offsets(
        &self,
        Parameters(p): Parameters<ExportOffsets>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("export_offsets", p).await
    }

    #[tool(
        description = "Run Ghidra auto-analysis on the program. all=true clears and reanalyzes everything (slow); all=false runs pending analysis only. Triggers RTTI, FunctionID, demangler, and every enabled analyzer. Raise --timeout-secs for large binaries",
        annotations(destructive_hint = false)
    )]
    async fn analyze_program(
        &self,
        Parameters(p): Parameters<AnalyzeProgram>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("analyze_program", p).await
    }

    #[tool(
        description = "List analysis option names and their on/off state. Use the names with set_analysis_option to enable analyzers (e.g. RTTI, 'Decompiler Parameter ID') before analyze_program",
        annotations(read_only_hint = true)
    )]
    async fn list_analyzers(&self) -> Result<CallToolResult, ErrorData> {
        self.get_bare("list_analyzers").await
    }

    #[tool(
        description = "Enable or disable an analysis option by its exact name (from list_analyzers), then call analyze_program to apply it",
        annotations(destructive_hint = false)
    )]
    async fn set_analysis_option(
        &self,
        Parameters(p): Parameters<SetAnalysisOption>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.name.is_empty() {
            return Err(ErrorData::invalid_params("name is required", None));
        }
        self.post("set_analysis_option", p).await
    }

    #[tool(
        description = "Apply a data type at an address: clears conflicting code/data and lays down the typed datum. type accepts builtins (int, char[16], void*) or any defined struct/enum/typedef name. Set clear=false to fail instead of overwriting",
        annotations(destructive_hint = false)
    )]
    async fn apply_data_type(
        &self,
        Parameters(p): Parameters<ApplyDataType>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("apply_data_type", p).await
    }

    #[tool(
        description = "Apply many data types in one call and one transaction. items is a JSON array of {address, type, clear?} where clear (default true) clears conflicting code/data at the address. Best-effort: a failing item is reported but does not roll back the others. Returns a per-item ok/fail report",
        annotations(destructive_hint = true)
    )]
    async fn batch_apply_data_type(
        &self,
        Parameters(p): Parameters<BatchItems>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.items.is_empty() {
            return Err(ErrorData::invalid_params("items is required", None));
        }
        self.post("batch_apply_data_type", p).await
    }

    #[tool(
        description = "Create a function at an address, disassembling and computing its body. Use on orphan code (see find_orphan_gaps) or a call target Ghidra missed",
        annotations(destructive_hint = false)
    )]
    async fn create_function(
        &self,
        Parameters(p): Parameters<Address>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("create_function", p).await
    }

    #[tool(
        description = "Commit the decompiler's inferred parameter, return, and local variable types/names into the program database for the function at this address. Locks in recovered types so callers and xrefs see them",
        annotations(destructive_hint = false)
    )]
    async fn propagate_function_types(
        &self,
        Parameters(p): Parameters<FunctionAddress>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("propagate_function_types", p).await
    }

    #[tool(
        description = "Edit a field of an existing structure at a byte offset. op=set (default): create/overwrite a field — mode=replace (default) overwrites whatever occupies the offset, mode=insert shifts later fields down; type accepts builtins or any defined type name; name optional. op=delete: replace the field at offset with undefined space (type/name ignored)",
        annotations(destructive_hint = false)
    )]
    async fn struct_field(
        &self,
        Parameters(p): Parameters<StructField>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.struct_name.is_empty() {
            return Err(ErrorData::invalid_params("struct_name is required", None));
        }
        if p.op.as_deref() != Some("delete") && p.data_type.is_none() {
            return Err(ErrorData::invalid_params(
                "type is required when op=set",
                None,
            ));
        }
        self.post("struct_field", p).await
    }

    #[tool(
        description = "Progressive disclosure: search this server's own tool catalog by keyword (matched against tool names and descriptions) and return matching name + description pairs. Use it to discover the right tool among the full set without loading every schema, then call get_tool_schema for the exact parameters. limit caps results (default 30)",
        annotations(read_only_hint = true)
    )]
    async fn search_tools(
        &self,
        Parameters(p): Parameters<SearchToolsArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let q = p.query.trim().to_lowercase();
        if q.is_empty() {
            return Err(ErrorData::invalid_params("query is required", None));
        }
        let limit = p.limit.unwrap_or(30).max(1) as usize;
        let mut matches: Vec<String> = Self::tool_router()
            .list_all()
            .into_iter()
            .filter(|t| {
                t.name.to_lowercase().contains(&q)
                    || t.description
                        .as_deref()
                        .is_some_and(|d| d.to_lowercase().contains(&q))
            })
            .map(|t| format!("{}\t{}", t.name, t.description.as_deref().unwrap_or("")))
            .collect();
        matches.sort();
        let total = matches.len();
        matches.truncate(limit);
        Ok(ok_text(format!(
            "# {total} match(es){}\nname\tdescription\n{}",
            if total > matches.len() {
                format!(" (showing {})", matches.len())
            } else {
                String::new()
            },
            matches.join("\n")
        )))
    }

    #[tool(
        description = "Progressive disclosure: return the full JSON input schema (parameters, types, descriptions) for a single tool by name, plus its description. Pair with search_tools to inspect a candidate tool's exact arguments on demand",
        annotations(read_only_hint = true)
    )]
    async fn get_tool_schema(
        &self,
        Parameters(p): Parameters<ToolName>,
    ) -> Result<CallToolResult, ErrorData> {
        let name = p.name.trim();
        match Self::tool_router()
            .list_all()
            .into_iter()
            .find(|t| t.name == name)
        {
            Some(t) => {
                let schema = serde_json::to_string_pretty(&*t.input_schema)
                    .unwrap_or_else(|_| "{}".to_owned());
                Ok(ok_text(format!(
                    "{}\n{}\n\n{schema}",
                    t.name,
                    t.description.as_deref().unwrap_or("")
                )))
            }
            None => Err(ErrorData::invalid_params(
                format!("unknown tool: {name} (use search_tools to discover names)"),
                None,
            )),
        }
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct AnalyzeFunctionArgs {
    pub address: String,
}

fn user_prompt(text: &str) -> Vec<PromptMessage> {
    vec![PromptMessage::new_text(Role::User, text.to_owned())]
}

#[prompt_router]
impl GhidraServer {
    #[prompt(
        name = "survey_binary",
        description = "Guided first-pass survey of the loaded program: layout, capabilities, IOCs, and what to reverse next"
    )]
    async fn survey_binary(&self) -> Vec<PromptMessage> {
        user_prompt(
            "Survey the program loaded in Ghidra and report findings.\n\
             1. program_info — arch, bits, base, sha256.\n\
             2. list_imports and list_strings — flag URLs, file paths, registry keys, suspicious APIs.\n\
             3. list_entry_points, then decompile (clean=true) each entry.\n\
             4. high_entropy_regions — packed/encrypted zones.\n\
             5. sample_intake then capability_map / recover_auth_surface / recover_hidden_strings / find_anti_debug.\n\
             6. find_undocumented, then function_summary_bundle on the worst-scored few.\n\
             Summarize: purpose, capabilities, IOCs, and the functions worth reversing next.",
        )
    }

    #[prompt(
        name = "analyze_function",
        description = "Deeply analyze and document one function at an address"
    )]
    async fn analyze_function(
        &self,
        params: Parameters<AnalyzeFunctionArgs>,
    ) -> Vec<PromptMessage> {
        user_prompt(&format!(
            "Analyze and document the function at {}.\n\
             1. function_summary_bundle {0} — decompile + callers + callees + strings in one call.\n\
             2. Infer purpose; name params/locals and pick a function name.\n\
             3. Apply with set_variables (new_name, prototype, variables) in one atomic call.\n\
             4. set_decompiler_comment with a one-line summary.\n\
             5. function_completeness {0} to confirm it scores well.\n\
             Recurse into the most important undocumented callee.",
            params.0.address
        ))
    }

    #[prompt(
        name = "triage_malware",
        description = "Malware triage workflow: anti-analysis, capabilities, encoded data, and crypto"
    )]
    async fn triage_malware(&self) -> Vec<PromptMessage> {
        user_prompt(
            "Triage this sample for malicious capabilities.\n\
             1. find_anti_debug + find_anti_vm — evasion; note what to neutralize.\n\
             2. find_api_hashes — resolve dynamically-imported APIs.\n\
             3. sample_intake deep=true — PE facts + packer + capa map + hidden strings in one shot.\n\
             4. capability_map / recover_auth_surface / recover_crypto_recipe / find_secret_compares.\n\
             5. recover_hidden_strings + decode_keystream on leftover blobs.\n\
             6. find_hash_blobs + find_self_modify + export_yara.\n\
             7. function_behavior on Login / payload / anti-debug — do NOT dump 1500-line decompiles first.\n\
             Map findings to likely behavior (persistence, C2, encryption, injection) and list IOCs.",
        )
    }

    #[prompt(
        name = "solve_crackme",
        description = "Recover the expected input/key of a check routine"
    )]
    async fn solve_crackme(&self) -> Vec<PromptMessage> {
        user_prompt(
            "Find and solve the validation routine.\n\
             1. find_secret_compares + find_check_function — strcmp/memcmp vs literals, license strings, fat immediates.\n\
             2. find_hash_blobs — hardcoded MD5/SHA-256 expected digests.\n\
             3. recover_crypto_recipe on the check function (HMAC / AES-GCM / hash).\n\
             4. function_behavior then extract_constraints on the compare.\n\
             5. emulate the check with candidate input, or solve the constraints by hand.\n\
             Report the accepted input and the exact branch that gates success.",
        )
    }

    #[prompt(
        name = "recover_types",
        description = "Recover symbols and types across the program"
    )]
    async fn recover_types(&self) -> Vec<PromptMessage> {
        user_prompt(
            "Recover symbols and types for the program.\n\
             1. list_analyzers; enable RTTI and Decompiler Parameter ID via set_analysis_option.\n\
             2. analyze_program to run recovery (RTTI classes, FunctionID, demangler).\n\
             3. demangle_all to clean up C++ names.\n\
             4. For hot functions: propagate_function_types to commit decompiler-inferred types.\n\
             5. find_undocumented; document the worst with set_variables + create_struct/apply_data_type.\n\
             Report recovered classes, named functions, and remaining gaps.",
        )
    }

    #[prompt(
        name = "bootstrap_dro_client",
        description = "Full Nebula3/Drakensang client bootstrap: survey, assert naming, TLS map, network surface"
    )]
    async fn bootstrap_dro_client(&self) -> Vec<PromptMessage> {
        user_prompt(
            "Bootstrap reverse-engineering of this Nebula3 / Drakensang Online client.\n\
             1. program_info + nebula_engine_survey — note sig_unique_auto_nameable and helpers.\n\
             2. seed_nebula_helpers apply=false then apply=true — auto-name n_assert/n_assert2/n_error/n_warning.\n\
             3. name_from_signatures apply=false (max=500+); review; apply=true. Loop until few remain.\n\
             4. name_from_n_assert mode=decompile for leftover assert callers; name_nebula_instances.\n\
             5. derive_tls_singletons (page offset until coverage=0) then apply=true; tls_singleton_map.\n\
             6. factory_catalog, assert_catalog, messaging_catalog, attr_catalog, source_tree, funcsig_graph.\n\
             7. find_function_by_string RakNet/DrasaOnlineClient/services; raknet_packet_lookup + decompile.\n\
             8. Read ghidra://dro/raknet-overview and ghidra://dro/nebula-playbook.\n\
             9. nebula_container_layout / prove_offset on hot containers; set_variables / propose_struct_from_accesses.\n\
             Deliver: helper table, rename counts (sigs + decomp + instances), TLS map, factory/assert/messaging catalogs, network dispatch, next targets.",
        )
    }

    #[prompt(
        name = "name_nebula_functions",
        description = "Mass-recover Nebula3 function names from signature strings and asserts"
    )]
    async fn name_nebula_functions(&self) -> Vec<PromptMessage> {
        user_prompt(
            "Recover Nebula3 symbols at scale.\n\
             1. seed_nebula_helpers if nebula_assert_helpers is empty/weak.\n\
             2. name_from_signatures apply=false then apply=true (fast path; no decompile).\n\
             3. name_from_n_assert mode=decompile apply=false then apply=true for leftovers.\n\
             4. name_nebula_instances for Type::Instance() singletons.\n\
             5. function_summary_bundle on key newly named methods; set_variables / propagate_function_types.\n\
             6. nebula_engine_survey — report remaining auto_named and sig_unique_auto_nameable.\n\
             Do not invent names for FUN_* that still have __cdecl signature strings or call n_assert.",
        )
    }

    #[prompt(
        name = "analyze_raknet_handler",
        description = "Map a RakNet packet id or handler address to DSO protocol knowledge and document it"
    )]
    async fn analyze_raknet_handler(
        &self,
        params: Parameters<AnalyzeFunctionArgs>,
    ) -> Vec<PromptMessage> {
        user_prompt(&format!(
            "Analyze the RakNet / DSO network handler at {} (or treat the value as a packet id if it looks like 0xNN).\n\
             1. If it looks like a packet id: raknet_packet_lookup id={{value}}; else function_summary_bundle {{addr}}.\n\
             2. Read ghidra://dro/raknet-packet-ids and ghidra://dro/raknet-flows for context.\n\
             3. Decompile the switch/dispatch and every case callees (clean=true).\n\
             4. Rename handlers with set_variables / name_from_n_assert when asserts exist.\n\
             5. batch_set_comment or analysis_note: packet id, direction, payload fields, next steps.\n\
             Report a id→name→function table for everything you touch.",
            params.0.address
        ))
    }
}

enum ResourceBody {
    Http(&'static str),
    StaticFn(fn() -> String),
}

type CatalogEntry = (&'static str, &'static str, ResourceBody);

const RESOURCES: &[CatalogEntry] = &[
    (
        "ghidra://program/info",
        "Program info",
        ResourceBody::Http("program_info"),
    ),
    (
        "ghidra://program/current-function",
        "Current function",
        ResourceBody::Http("get_current_function"),
    ),
    (
        "ghidra://program/current-address",
        "Current address",
        ResourceBody::Http("get_current_address"),
    ),
    (
        "ghidra://debugger/status",
        "Debugger status (live)",
        ResourceBody::Http("debugger_status"),
    ),
    (
        "ghidra://dro/raknet-overview",
        "DSO RakNet overview",
        ResourceBody::StaticFn(crate::dro::overview_markdown),
    ),
    (
        "ghidra://dro/raknet-packet-ids",
        "DSO RakNet packet ID table",
        ResourceBody::StaticFn(crate::dro::packet_ids_markdown),
    ),
    (
        "ghidra://dro/raknet-flows",
        "DSO RakNet in-game flows",
        ResourceBody::StaticFn(crate::dro::packet_flows_markdown),
    ),
    (
        "ghidra://dro/nebula-playbook",
        "Nebula3 / DRO RE playbook",
        ResourceBody::StaticFn(nebula_playbook_markdown),
    ),
];

fn nebula_playbook_markdown() -> String {
    r"# Nebula3 / Drakensang Online RE playbook

## Always-on mental model
- Engine: **Nebula3** (gscept/nebula-trifid lineage) + game layer **Drasa** / DSO.
- Smart pointers: `Core::Ptr<T>` (often decompiles as vtable thrash + refcount).
- Interned strings: `StringAtom` / atom tables — search raw text if not defined strings.
- Containers: `Util::Array` / `FixedArray` / `Dictionary` — use `nebula_container_layout`.
- Diagnostics: `n_assert` / `n_error` / `n_warning` embed **file, line, full C++ signature**.

## First 10 minutes on a new binary
1. `nebula_engine_survey` — note `sig_unique_auto_nameable` (often 10k+)
2. `seed_nebula_helpers` dry-run → `apply=true` (n_assert / n_assert2 / n_error / n_warning)
3. `name_from_signatures` dry-run → `apply=true` with high max (fast; no decompile)
4. `name_from_n_assert` mode=decompile for leftovers that only show up in assert calls
5. `name_nebula_instances` for Type::Instance() singletons
6. `derive_tls_singletons` page until coverage=0, then `apply=true`; `tls_singleton_map`
7. Indexes (no guessing): `factory_catalog` · `assert_catalog` · `messaging_catalog` · `attr_catalog` · `source_tree` · `funcsig_graph`
8. Network: `raknet_packet_lookup` + `messaging_catalog filter=UseItem` — wire is still 0x8b
9. `save_program`

## How to search (do not decompile a random FUN_*)
- Field on a class → `prove_offset` / `assert_catalog prove=true filter=…`
- Live object → `list_nebula_instances` → `derive_tls_singletons class=…` → `tls:SLOT`
- Player action → `messaging_catalog` → `*HandleMessage*` → raknet 0x8b
- Gold / item / wallet → `attr_catalog` (`money_rc` is gold). Not a C++ field.
- Class / FourCC → `factory_catalog` (MSVC RTTI here is PathEngine only)
- Subsystem → `source_tree filter=shared/skills` or `funcsig_graph filter=Skills`

## Naming rules
- Prefer `name_from_signatures` for bulk Nebula C++ names (signature string xrefs).
- Prefer `name_from_n_assert` mode=decompile for assert-callers the string pass missed.
- Sanitized names: `IO_Console_Warning`, templates `Core_Ptr6T9`, operators `…_operator`.
- Plate comments get `path:line | signature` when apply=true.

## TLS singleton map (static offsets into module TLS)
| slot | type | role |
|---|---|---|
| +0x58 | Game::ClientGameWorld* | local player / world |
| +0x60 | Game::DrasaClient* | client root |
| +0x90 | Game::ClientActorManager* | nearby entities |
| +0x5b0 | Managers::TemplateManager* | templates |
| +0x5e0 | Skills::SkillManager* | skills |
| +0x300 | CoreGraphics::TransformDevice* | W2S |
| +0x6b0 | Game::EntityManager* | entity ids |
See tool `tls_singleton_map` for the full table. `derive_tls_singletons apply=true` persists more.

## Network
Resources: `ghidra://dro/raknet-overview`, `…/raknet-packet-ids`, `…/raknet-flows`.
Tool: `raknet_packet_lookup`. Custom game IDs live in **0x82–0x8e**.
Local protocol is `Messaging::*` (see `messaging_catalog`); `NetworkCommandCreatorProperty::HandleMessage` encodes C→S.

## Decomp hygiene
- `address_context` before reading bytes at an interior VA
- `reachability` — `.pdata` is not a call; `.CRT$XCU` / atexit is `crt_init`, not dead
- `decompile` / `function_summary_bundle` with clean=true
- `refine_function` then `set_variables` for prototypes
- `nebula_shape` / `nebula_container_layout` before inventing Array field layouts
"
    .to_owned()
}

fn complete_resource_uris(prefix: &str) -> Vec<String> {
    let needle = prefix.trim().to_ascii_lowercase();
    RESOURCES
        .iter()
        .map(|(uri, ..)| (*uri).to_owned())
        .filter(|uri| needle.is_empty() || uri.to_ascii_lowercase().contains(&needle))
        .take(COMPLETE_LIMIT)
        .collect()
}

fn complete_prompt_names(prefix: &str) -> Vec<String> {
    let needle = prefix.trim().to_ascii_lowercase();
    GhidraServer::prompt_router()
        .list_all()
        .into_iter()
        .map(|p| p.name)
        .filter(|name| needle.is_empty() || name.to_ascii_lowercase().contains(&needle))
        .take(COMPLETE_LIMIT)
        .collect()
}

fn complete_result(values: Vec<String>) -> Result<CompleteResult, ErrorData> {
    let has_more = false;
    let completion = CompletionInfo::with_pagination(values, None, has_more)
        .map_err(|e| ErrorData::internal_error(e, None))?;
    Ok(CompleteResult::new(completion))
}

#[tool_handler]
#[prompt_handler]
impl ServerHandler for GhidraServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_prompts()
                .enable_resources()
                .enable_completions()
                .build(),
        )
        .with_protocol_version(ProtocolVersion::V_2026_07_28)
        .with_server_info(Implementation::new("ghidra-mcp", env!("CARGO_PKG_VERSION")))
        .with_instructions(
            "Rust-based MCP bridge to the GhidraMCP HTTP plugin. Speaks MCP 2026-07-28 \
             (server/discover, per-request _meta, cache hints, completions) and remains \
             compatible with 2025-11-25 and earlier via initialize. Tools decompile, \
             disassemble, search, and annotate; prompts give guided RE workflows; \
             resources expose live program and debugger state plus Nebula3/DSO domain knowledge.\n\n\
             Addressing: tools take a full VA, an interior address (resolves to the enclosing \
             function), or an RVA. A small value that is not a mapped VA is auto-rebased to \
             image_base+value; force RVA interpretation with an `rva:` prefix (e.g. rva:0x2d202c). \
             See image_base via program_info.\n\n\
             Strings: list_strings / search kind=string / find_function_by_string cover only DEFINED \
             program strings; for undefined or embedded text (content ids, locale keys, asset names) \
             use search kind=text (ASCII + UTF-16LE raw-memory scan).\n\n\
             Nebula3 / Drakensang Online (primary target):\n\
             - Start with nebula_engine_survey and resource ghidra://dro/nebula-playbook.\n\
             - Bulk symbols: seed_nebula_helpers → name_from_signatures (no decompile, 10k+ scale) → \
             name_from_n_assert mode=decompile for leftovers → name_nebula_instances.\n\
             - Indexes: factory_catalog (class+FourCC+RTTI), assert_catalog (this-> fields), \
             messaging_catalog, attr_catalog (money_rc is gold), source_tree, funcsig_graph.\n\
             - Offsets: prove_offset / assert_catalog prove=true — never guess this+0x??.\n\
             - TLS: derive_tls_singletons then tls_singleton_map (TLS+0x58 world, +0x5e0 skills, …).\n\
             - Asserts/signatures embed full C++ names + source paths; never invent FUN_* names first.\n\
             - Expect Core::Ptr<T>, StringAtom, Util::Array/FixedArray/Dictionary — use \
             nebula_shape and nebula_container_layout.\n\
             - Network is RakNet + DSO custom 0x82–0x8e plus Messaging::* classes: \
             raknet_packet_lookup, messaging_catalog, ghidra://dro/raknet-* resources.\n\
             - Prompts: bootstrap_dro_client, name_nebula_functions, analyze_raknet_handler."
                .to_owned(),
        )
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(SUPPORTED_PROTOCOL_VERSIONS)
    }

    async fn discover(
        &self,
        _context: RequestContext<RoleServer>,
    ) -> Result<DiscoverResult, ErrorData> {
        Ok(
            DiscoverResult::from_server_info(SUPPORTED_PROTOCOL_VERSIONS.to_vec(), self.get_info())
                .with_ttl_ms(CATALOG_TTL_MS)
                .with_cache_scope(CacheScope::Public),
        )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        Ok(
            ListToolsResult::with_all_items(Self::tool_router().list_all())
                .with_ttl_ms(CATALOG_TTL_MS)
                .with_cache_scope(CacheScope::Public),
        )
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        let resources = RESOURCES
            .iter()
            .map(|(uri, name, body)| {
                let mime = match body {
                    ResourceBody::StaticFn(_) => "text/markdown",
                    ResourceBody::Http(_) => "text/plain",
                };
                Resource::new(*uri, *name).with_mime_type(mime)
            })
            .collect();
        Ok(ListResourcesResult::with_all_items(resources)
            .with_ttl_ms(CATALOG_TTL_MS)
            .with_cache_scope(CacheScope::Public))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        let Some((uri, _, body)) = RESOURCES.iter().find(|(uri, ..)| *uri == request.uri) else {
            return Err(ErrorData::resource_not_found(
                format!("unknown resource: {}", request.uri),
                None,
            ));
        };
        let (text, ttl_ms, scope) = match body {
            ResourceBody::Http(endpoint) => (
                self.http
                    .get(endpoint, NO_QUERY)
                    .await
                    .map_err(resource_err)?,
                LIVE_RESOURCE_TTL_MS,
                CacheScope::Private,
            ),
            ResourceBody::StaticFn(f) => (f(), STATIC_RESOURCE_TTL_MS, CacheScope::Public),
        };
        Ok(
            ReadResourceResult::new(vec![ResourceContents::text(text, *uri)])
                .with_ttl_ms(ttl_ms)
                .with_cache_scope(scope)
                .into(),
        )
    }

    async fn complete(
        &self,
        request: CompleteRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CompleteResult, ErrorData> {
        let arg = request.argument.name.as_str();
        let value = request.argument.value.as_str();
        let values = match &request.r#ref {
            Reference::Resource(resource) => {
                let seed = if value.is_empty() {
                    resource.uri.as_str()
                } else {
                    value
                };
                complete_resource_uris(seed)
            }
            Reference::Prompt(prompt)
                if arg == "address"
                    && matches!(
                        prompt.name.as_str(),
                        "analyze_function" | "analyze_raknet_handler"
                    ) =>
            {
                self.complete_functions(value).await
            }
            Reference::Prompt(_) => complete_prompt_names(value),
            _ => Vec::new(),
        };
        complete_result(values)
    }
}

impl GhidraServer {
    async fn complete_functions(&self, query: &str) -> Vec<String> {
        let q = query.trim();
        if q.is_empty() {
            return Vec::new();
        }
        let params = [
            ("query", q.to_owned()),
            ("limit", COMPLETE_LIMIT.to_string()),
        ];
        let Ok(body) = self.http.get("search_functions", &params).await else {
            return Vec::new();
        };
        body.lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .filter_map(|line| {
                let col = line.split('\t').next().unwrap_or(line).trim();
                if col.is_empty() || col == "name" || col == "addr" {
                    None
                } else {
                    Some(col.to_owned())
                }
            })
            .take(COMPLETE_LIMIT)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn hash_algo_default_is_fnv1a() {
        assert!(matches!(HashAlgo::default(), HashAlgo::Fnv1a));
    }

    #[test]
    fn hash_algo_as_str_round_trips_each_variant() {
        assert_eq!(HashAlgo::Fnv1a.as_str(), "fnv1a");
        assert_eq!(HashAlgo::Fnv1aLower.as_str(), "fnv1a_lower");
        assert_eq!(HashAlgo::Djb2.as_str(), "djb2");
        assert_eq!(HashAlgo::Crc32.as_str(), "crc32");
    }

    #[test]
    fn page_uses_default_limit_when_absent() {
        let p: Page = serde_json::from_str("{}").unwrap();
        assert_eq!(p.offset, 0);
        assert_eq!(p.limit, default_limit());
    }

    #[test]
    fn read_bytes_defaults_length() {
        let p: ReadBytes = serde_json::from_str(r#"{"address":"0x1000"}"#).unwrap();
        assert_eq!(p.length, default_read_length());
    }

    #[test]
    fn list_strings_defaults_limit_and_omits_filter() {
        let p: ListStrings = serde_json::from_str("{}").unwrap();
        assert_eq!(p.limit, default_strings_limit());
        assert!(p.filter.is_none());
    }

    #[test]
    fn list_strings_emits_regex_xrefs_fmt_and_program() {
        let p = ListStrings {
            offset: 3,
            limit: 7,
            filter: Some("MagicSlot_.*".to_owned()),
            regex: Some(true),
            xrefs: Some(true),
            fmt: Some("json".to_owned()),
            program: Some("sample.exe".to_owned()),
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("offset", "3".to_owned()),
                ("limit", "7".to_owned()),
                ("filter", "MagicSlot_.*".to_owned()),
                ("regex", "1".to_owned()),
                ("xrefs", "1".to_owned()),
                ("fmt", "json".to_owned()),
                ("program", "sample.exe".to_owned()),
            ]
        );
    }

    #[test]
    fn page_into_params_emits_offset_and_limit() {
        let p = Page {
            offset: 5,
            limit: 9,
            fmt: None,
            program: None,
            ..Default::default()
        };
        assert_eq!(
            p.into_params(),
            vec![("offset", "5".to_owned()), ("limit", "9".to_owned())]
        );
    }

    #[test]
    fn page_into_params_appends_program_when_set() {
        let p = Page {
            offset: 0,
            limit: 10,
            fmt: None,
            program: Some("variant_b.exe".to_owned()),
            ..Default::default()
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("offset", "0".to_owned()),
                ("limit", "10".to_owned()),
                ("program", "variant_b.exe".to_owned()),
            ]
        );
    }

    #[test]
    fn page_into_params_appends_fmt_when_set() {
        let p = Page {
            offset: 0,
            limit: 10,
            fmt: Some("json".to_owned()),
            program: None,
            ..Default::default()
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("offset", "0".to_owned()),
                ("limit", "10".to_owned()),
                ("fmt", "json".to_owned()),
            ]
        );
    }

    #[test]
    fn address_page_composes_page_params_then_address() {
        let p = AddressPage {
            address: "0x401000".to_owned(),
            page: Page {
                offset: 0,
                limit: 50,
                fmt: None,
                program: None,
                ..Default::default()
            },
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("offset", "0".to_owned()),
                ("limit", "50".to_owned()),
                ("address", "0x401000".to_owned()),
            ]
        );
    }

    #[test]
    fn apply_naming_convention_emits_convention_and_apply_flag() {
        let p = ApplyNamingConvention {
            convention: NamingConvention::ScreamingSnake,
            namespace: None,
            apply: true,
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("convention", "screaming_snake".to_owned()),
                ("apply", "1".to_owned()),
            ]
        );
    }

    #[test]
    fn apply_naming_convention_dry_run_includes_namespace() {
        let p = ApplyNamingConvention {
            convention: NamingConvention::Snake,
            namespace: Some("Crypto".to_owned()),
            apply: false,
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("convention", "snake".to_owned()),
                ("namespace", "Crypto".to_owned()),
                ("apply", "0".to_owned()),
            ]
        );
    }

    #[test]
    fn name_from_n_assert_params_dry_run() {
        let p = NameFromNAssert {
            address: None,
            apply: false,
            max: 200,
            mode: None,
        };
        assert_eq!(
            p.into_params(),
            vec![("apply", "0".to_owned()), ("max", "200".to_owned())]
        );
    }

    #[test]
    fn name_from_n_assert_params_with_address() {
        let p = NameFromNAssert {
            address: Some("rva:0x1234".to_owned()),
            apply: true,
            max: 50,
            mode: Some("decompile".to_owned()),
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("apply", "1".to_owned()),
                ("max", "50".to_owned()),
                ("address", "rva:0x1234".to_owned()),
                ("mode", "decompile".to_owned()),
            ]
        );
    }

    #[test]
    fn prove_offset_params_omit_blank_selectors() {
        let p = ProveOffsetArgs {
            address: Some("   ".to_owned()),
            field: Some("summonMonsterAmount".to_owned()),
            class: None,
            proven_only: Some(true),
            max: 25,
            page: Page {
                offset: 0,
                limit: 100,
                fmt: None,
                program: None,
                ..Default::default()
            },
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("offset", "0".to_owned()),
                ("limit", "100".to_owned()),
                ("max", "25".to_owned()),
                ("field", "summonMonsterAmount".to_owned()),
                ("proven_only", "1".to_owned()),
            ]
        );
    }

    #[test]
    fn address_context_params_carry_count_and_bytes() {
        let p = AddressContextArgs {
            address: "rva:0x8b703d".to_owned(),
            count: 4,
            bytes: 16,
            fmt: Some("tsv".to_owned()),
            program: None,
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("address", "rva:0x8b703d".to_owned()),
                ("count", "4".to_owned()),
                ("bytes", "16".to_owned()),
                ("fmt", "tsv".to_owned()),
            ]
        );
    }

    #[test]
    fn reachability_params_carry_depth_and_max() {
        let p = ReachabilityArgs {
            target: "1408b703c".to_owned(),
            depth: 6,
            max: 400,
            fmt: None,
            program: Some("dro_client64.exe".to_owned()),
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("target", "1408b703c".to_owned()),
                ("depth", "6".to_owned()),
                ("max", "400".to_owned()),
                ("program", "dro_client64.exe".to_owned()),
            ]
        );
    }

    #[test]
    fn nebula_shape_params_are_empty_without_selectors() {
        let p = NebulaShapeArgs {
            address: None,
            kind: None,
            fmt: None,
            program: None,
        };
        assert!(p.into_params().is_empty());
    }

    #[test]
    fn derive_tls_singletons_params_page_then_max() {
        let p = DeriveTlsSingletonsArgs {
            class: Some("SkillManager".to_owned()),
            max: 30,
            apply: false,
            page: Page {
                offset: 30,
                limit: 100,
                fmt: None,
                program: None,
                ..Default::default()
            },
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("offset", "30".to_owned()),
                ("limit", "100".to_owned()),
                ("max", "30".to_owned()),
                ("class", "SkillManager".to_owned()),
            ]
        );
    }

    #[test]
    fn catalog_filter_omits_blank_filter() {
        let p = CatalogFilter {
            filter: Some("  ".to_owned()),
            page: Page {
                offset: 0,
                limit: 50,
                fmt: None,
                program: None,
                ..Default::default()
            },
        };
        assert_eq!(
            p.into_params(),
            vec![("offset", "0".to_owned()), ("limit", "50".to_owned())]
        );
    }

    #[test]
    fn assert_catalog_params_carry_prove() {
        let p = AssertCatalogArgs {
            filter: Some("currState".to_owned()),
            prove: Some(true),
            max: 40,
            page: Page {
                offset: 0,
                limit: 100,
                fmt: None,
                program: None,
                ..Default::default()
            },
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("offset", "0".to_owned()),
                ("limit", "100".to_owned()),
                ("max", "40".to_owned()),
                ("filter", "currState".to_owned()),
                ("prove", "1".to_owned()),
            ]
        );
    }

    #[test]
    fn graph_max_funcsig_source() {
        let p = GraphMax {
            max: Some(80),
            source: Some("funcsig".to_owned()),
            filter: Some("Skills".to_owned()),
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("max", "80".to_owned()),
                ("source", "funcsig".to_owned()),
                ("filter", "Skills".to_owned()),
            ]
        );
    }

    #[test]
    fn parse_packet_id_accepts_hex_and_decimal() {
        assert_eq!(parse_packet_id("0x8a").unwrap(), 0x8a);
        assert_eq!(parse_packet_id("8a").unwrap(), 0x8a);
        assert_eq!(parse_packet_id("138").unwrap(), 138);
    }

    #[test]
    fn dro_resources_are_registered() {
        let uris: Vec<&str> = RESOURCES.iter().map(|(u, ..)| *u).collect();
        assert!(uris.contains(&"ghidra://dro/raknet-overview"));
        assert!(uris.contains(&"ghidra://dro/raknet-packet-ids"));
        assert!(uris.contains(&"ghidra://dro/raknet-flows"));
        assert!(uris.contains(&"ghidra://dro/nebula-playbook"));
    }

    #[test]
    fn readme_tool_count_matches_catalog() {
        let n = GhidraServer::tool_router().list_all().len();
        let readme = include_str!("../README.md");
        let expected = format!("{n} tools total.");
        assert!(
            readme.contains(&expected),
            "README is out of sync: it must state \"{expected}\" (catalog has {n} tools)"
        );
    }

    fn readme_tools_section() -> &'static str {
        let readme = include_str!("../README.md");
        readme
            .split_once("## Tools")
            .and_then(|(_, rest)| rest.split_once("\n## "))
            .map(|(section, _)| section)
            .unwrap()
    }

    fn readme_table_tool_names() -> Vec<String> {
        readme_tools_section()
            .lines()
            .filter_map(|line| line.trim_start().strip_prefix("| `"))
            .filter_map(|rest| rest.split_once('`').map(|(name, _)| name.to_owned()))
            .collect()
    }

    #[test]
    fn every_tool_has_a_readme_table_row() {
        let documented: std::collections::HashSet<String> =
            readme_table_tool_names().into_iter().collect();
        let missing: Vec<String> = GhidraServer::tool_router()
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .filter(|name| !documented.contains(name))
            .collect();
        assert!(
            missing.is_empty(),
            "tools missing a README table row: {missing:?}"
        );
    }

    #[test]
    fn no_stale_tools_in_readme_table() {
        let catalog: std::collections::HashSet<String> = GhidraServer::tool_router()
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        let stale: Vec<String> = readme_table_tool_names()
            .into_iter()
            .filter(|name| !catalog.contains(name))
            .collect();
        assert!(
            stale.is_empty(),
            "README table lists tools not in the catalog: {stale:?}"
        );
    }

    #[test]
    fn tool_router_introspects_catalog() {
        let names: Vec<String> = GhidraServer::tool_router()
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        assert!(names.iter().any(|n| n == "list_functions"));
        assert!(names.iter().any(|n| n == "search_tools"));
        assert!(names.iter().any(|n| n == "get_tool_schema"));
        assert!(
            names.len() >= 140,
            "expected full catalog, got {}",
            names.len()
        );
    }

    #[test]
    fn propagate_matches_emits_program_and_apply_flag() {
        let p = PropagateMatches {
            program_b: "variant_b.exe".to_owned(),
            apply: true,
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("program_b", "variant_b.exe".to_owned()),
                ("apply", "1".to_owned()),
            ]
        );
    }

    #[test]
    fn diff_programs_emits_program_b_with_page() {
        let p = DiffPrograms {
            program_b: "variant_b.exe".to_owned(),
            page: Page {
                offset: 0,
                limit: 100,
                fmt: None,
                program: None,
                ..Default::default()
            },
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("offset", "0".to_owned()),
                ("limit", "100".to_owned()),
                ("program_b", "variant_b.exe".to_owned()),
            ]
        );
    }

    #[test]
    fn diff_functions_emits_addresses_and_optional_program() {
        let p = DiffFunctions {
            address_a: "0x401000".to_owned(),
            address_b: "0x401500".to_owned(),
            program_b: Some("variant_b.exe".to_owned()),
            mode: None,
            clean: None,
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("address_a", "0x401000".to_owned()),
                ("address_b", "0x401500".to_owned()),
                ("program_b", "variant_b.exe".to_owned()),
            ]
        );
    }

    #[test]
    fn diff_functions_omits_program_b_when_same_program() {
        let p = DiffFunctions {
            address_a: "0x401000".to_owned(),
            address_b: "0x402000".to_owned(),
            program_b: None,
            mode: None,
            clean: None,
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("address_a", "0x401000".to_owned()),
                ("address_b", "0x402000".to_owned()),
            ]
        );
    }

    #[test]
    fn coverage_report_emits_path_with_page() {
        let p = Coverage {
            op: None,
            path: "cov.txt".to_owned(),
            path_a: String::new(),
            path_b: String::new(),
            page: Page {
                offset: 0,
                limit: 100,
                fmt: None,
                program: None,
                ..Default::default()
            },
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("offset", "0".to_owned()),
                ("limit", "100".to_owned()),
                ("path", "cov.txt".to_owned()),
            ]
        );
    }

    #[test]
    fn coverage_diff_emits_both_paths() {
        let p = Coverage {
            op: Some("diff".to_owned()),
            path: String::new(),
            path_a: "a.txt".to_owned(),
            path_b: "b.txt".to_owned(),
            page: Page {
                offset: 0,
                limit: 100,
                fmt: None,
                program: None,
                ..Default::default()
            },
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("offset", "0".to_owned()),
                ("limit", "100".to_owned()),
                ("op", "diff".to_owned()),
                ("path_a", "a.txt".to_owned()),
                ("path_b", "b.txt".to_owned()),
            ]
        );
    }

    #[test]
    fn propose_struct_emits_function_and_variable() {
        let p = ProposeStruct {
            function_address: "0x401000".to_owned(),
            variable: "param_1".to_owned(),
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("function_address", "0x401000".to_owned()),
                ("variable", "param_1".to_owned()),
            ]
        );
    }

    #[test]
    fn emulate_function_emits_address_args_capture() {
        let p = EmulateFunction {
            function_address: "0x401000".to_owned(),
            args: Some("0x10,42".to_owned()),
            max_steps: None,
            capture_addr: Some("0x40a000".to_owned()),
            capture_length: 32,
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("function_address", "0x401000".to_owned()),
                ("capture_length", "32".to_owned()),
                ("args", "0x10,42".to_owned()),
                ("capture_addr", "0x40a000".to_owned()),
            ]
        );
    }

    #[test]
    fn recover_hidden_strings_emits_optional_fields() {
        let p = RecoverHiddenStrings {
            address: Some("0x140007df0".to_owned()),
            algo: Some("splitmix".to_owned()),
            min_len: Some(6),
            apply: Some(true),
            page: Page {
                offset: 0,
                limit: 50,
                fmt: None,
                program: None,
                ..Default::default()
            },
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("offset", "0".to_owned()),
                ("limit", "50".to_owned()),
                ("address", "0x140007df0".to_owned()),
                ("algo", "splitmix".to_owned()),
                ("min_len", "6".to_owned()),
                ("apply", "1".to_owned()),
            ]
        );
    }

    #[test]
    fn function_behavior_emits_address_and_page() {
        let p = FunctionBehavior {
            address: "0x140007df0".to_owned(),
            page: Page {
                offset: 0,
                limit: 100,
                fmt: None,
                program: None,
                ..Default::default()
            },
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("offset", "0".to_owned()),
                ("limit", "100".to_owned()),
                ("address", "0x140007df0".to_owned()),
            ]
        );
    }

    #[test]
    fn sample_intake_emits_deep() {
        let p = SampleIntake {
            deep: Some(true),
            page: Page {
                offset: 0,
                limit: 50,
                fmt: None,
                program: None,
                ..Default::default()
            },
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("offset", "0".to_owned()),
                ("limit", "50".to_owned()),
                ("deep", "1".to_owned()),
            ]
        );
    }

    #[test]
    fn decode_keystream_emits_seed_and_algo() {
        let p = DecodeKeystream {
            address: "0x1401947f0".to_owned(),
            length: 16,
            seed: "0x79c692957d38084c".to_owned(),
            algo: Some("splitmix".to_owned()),
            increment: 1,
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("address", "0x1401947f0".to_owned()),
                ("length", "16".to_owned()),
                ("seed", "0x79c692957d38084c".to_owned()),
                ("increment", "1".to_owned()),
                ("algo", "splitmix".to_owned()),
            ]
        );
    }

    #[test]
    fn export_yara_emits_format_name_deep() {
        let p = ExportYara {
            format: Some("yara".to_owned()),
            name: Some("Mortis".to_owned()),
            deep: Some(true),
            page: Page {
                offset: 0,
                limit: 100,
                fmt: None,
                program: None,
                ..Default::default()
            },
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("offset", "0".to_owned()),
                ("limit", "100".to_owned()),
                ("format", "yara".to_owned()),
                ("name", "Mortis".to_owned()),
                ("deep", "1".to_owned()),
            ]
        );
    }

    #[test]
    fn extract_iocs_emits_scope() {
        let p = ExtractIocs {
            scope: Some("both".to_owned()),
            page: Page {
                offset: 0,
                limit: 50,
                fmt: None,
                program: None,
                ..Default::default()
            },
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("offset", "0".to_owned()),
                ("limit", "50".to_owned()),
                ("scope", "both".to_owned()),
            ]
        );
    }

    #[test]
    fn recover_decoded_strings_emits_set_fields_only() {
        let p = RecoverDecodedStrings {
            function_address: "0x401000".to_owned(),
            args: Some("0x40a000".to_owned()),
            min_len: Some(5),
            max_steps: None,
            output_addr: Some("0x40b000".to_owned()),
            output_length: None,
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("function_address", "0x401000".to_owned()),
                ("args", "0x40a000".to_owned()),
                ("min_len", "5".to_owned()),
                ("output_addr", "0x40b000".to_owned()),
            ]
        );
    }

    #[test]
    fn emu_start_emits_start_and_optional_stack() {
        let p = EmuStart {
            start: "0x401000".to_owned(),
            stack: Some("0x7fff0000".to_owned()),
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("start", "0x401000".to_owned()),
                ("stack", "0x7fff0000".to_owned()),
            ]
        );
    }

    #[test]
    fn emu_session_run_to_emits_op_id_stop() {
        let p = EmuSession {
            op: "run_to".to_owned(),
            emu_id: "emu3".to_owned(),
            count: None,
            stop: Some("0x401050".to_owned()),
            max_steps: None,
            full: None,
            register: None,
            value: None,
            address: None,
            length: None,
            hex: None,
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("op", "run_to".to_owned()),
                ("emu_id", "emu3".to_owned()),
                ("stop", "0x401050".to_owned()),
            ]
        );
    }

    #[test]
    fn emu_session_setreg_emits_register_and_value() {
        let p = EmuSession {
            op: "setreg".to_owned(),
            emu_id: "emu1".to_owned(),
            count: None,
            stop: None,
            max_steps: None,
            full: None,
            register: Some("RDI".to_owned()),
            value: Some("0x10".to_owned()),
            address: None,
            length: None,
            hex: None,
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("op", "setreg".to_owned()),
                ("emu_id", "emu1".to_owned()),
                ("register", "RDI".to_owned()),
                ("value", "0x10".to_owned()),
            ]
        );
    }

    #[test]
    fn pointer_scan_emits_target_with_optional_bounds() {
        let p = PointerScanArgs {
            target: "0x140025000".to_owned(),
            max_offset: Some(2048),
            limit: Some(50),
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("target", "0x140025000".to_owned()),
                ("max_offset", "2048".to_owned()),
                ("limit", "50".to_owned()),
            ]
        );
    }

    #[test]
    fn pointer_scan_omits_unset_bounds() {
        let p = PointerScanArgs {
            target: "0x401000".to_owned(),
            max_offset: None,
            limit: None,
        };
        assert_eq!(p.into_params(), vec![("target", "0x401000".to_owned())]);
    }

    #[test]
    fn read_pointer_path_emits_base_offsets_value_len() {
        let p = ReadPointerPath {
            base: "0x140000000".to_owned(),
            offsets: Some("0x18,0x40".to_owned()),
            value_len: Some(8),
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("base", "0x140000000".to_owned()),
                ("offsets", "0x18,0x40".to_owned()),
                ("value_len", "8".to_owned()),
            ]
        );
    }

    #[test]
    fn opt_u32_accepts_string_number_and_hex() {
        let from_str: ReadPointerPath =
            serde_json::from_str(r#"{"base":"0x1000","value_len":"8"}"#).unwrap();
        assert_eq!(from_str.value_len, Some(8));
        let from_num: ReadPointerPath =
            serde_json::from_str(r#"{"base":"0x1000","value_len":8}"#).unwrap();
        assert_eq!(from_num.value_len, Some(8));
        let from_hex: ReadPointerPath =
            serde_json::from_str(r#"{"base":"0x1000","value_len":"0x10"}"#).unwrap();
        assert_eq!(from_hex.value_len, Some(16));
        let absent: ReadPointerPath = serde_json::from_str(r#"{"base":"0x1000"}"#).unwrap();
        assert_eq!(absent.value_len, None);
    }

    #[test]
    fn read_pointer_path_omits_optional_fields() {
        let p = ReadPointerPath {
            base: "0x140001000".to_owned(),
            offsets: None,
            value_len: None,
        };
        assert_eq!(p.into_params(), vec![("base", "0x140001000".to_owned())]);
    }

    #[test]
    fn patch_bytes_emits_disassemble_flag() {
        let p = PatchBytes {
            address: "0x401000".to_owned(),
            hex: "90 90".to_owned(),
            disassemble: true,
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("address", "0x401000".to_owned()),
                ("hex", "90 90".to_owned()),
                ("disassemble", "1".to_owned()),
            ]
        );
    }

    #[test]
    fn write_artifact_emits_path_and_content() {
        let p = WriteArtifact {
            path: "artifacts/live.tsv".to_owned(),
            content: "addr\tvalue\n".to_owned(),
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("path", "artifacts/live.tsv".to_owned()),
                ("content", "addr\tvalue\n".to_owned()),
            ]
        );
    }

    #[test]
    fn live_read_struct_emits_address_and_schema() {
        let p = LiveReadStruct {
            address: "0x1000".to_owned(),
            schema: "pos: vec3 +0x34".to_owned(),
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("address", "0x1000".to_owned()),
                ("schema", "pos: vec3 +0x34".to_owned()),
            ]
        );
    }

    #[test]
    fn search_appends_start_cursor_when_set() {
        let p = Search {
            kind: "bytes".to_owned(),
            query: "48 8B ??".to_owned(),
            start: Some("0x401234".to_owned()),
            page: Page {
                offset: 0,
                limit: 20,
                fmt: None,
                program: None,
                ..Default::default()
            },
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("offset", "0".to_owned()),
                ("limit", "20".to_owned()),
                ("kind", "bytes".to_owned()),
                ("query", "48 8B ??".to_owned()),
                ("start", "0x401234".to_owned()),
            ]
        );
    }

    #[test]
    fn rename_function_emits_kind_and_new_name() {
        let p = Rename {
            kind: None,
            new_name: "decode".to_owned(),
            old_name: Some("sub_401000".to_owned()),
            address: None,
            function_name: None,
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("new_name", "decode".to_owned()),
                ("old_name", "sub_401000".to_owned()),
            ]
        );
    }

    #[test]
    fn make_signature_emits_address_maxlen_format() {
        let p = MakeSignature {
            address: "0x401000".to_owned(),
            min_len: 8,
            max_len: 64,
            format: "ida".to_owned(),
            mode: Some("semantic".to_owned()),
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("address", "0x401000".to_owned()),
                ("min_len", "8".to_owned()),
                ("max_len", "64".to_owned()),
                ("format", "ida".to_owned()),
                ("mode", "semantic".to_owned()),
            ]
        );
    }

    #[test]
    fn search_signature_composes_page_kind_query() {
        let p = Search {
            kind: "signature".to_owned(),
            query: "48 8B ?? E8".to_owned(),
            start: None,
            page: Page {
                offset: 0,
                limit: 20,
                fmt: None,
                program: None,
                ..Default::default()
            },
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("offset", "0".to_owned()),
                ("limit", "20".to_owned()),
                ("kind", "signature".to_owned()),
                ("query", "48 8B ?? E8".to_owned()),
            ]
        );
    }

    #[test]
    fn find_function_by_string_defaults() {
        let p: FindFunctionByString = serde_json::from_str(r#"{"value":"licen"}"#).unwrap();
        assert_eq!(p.max, default_ffbs_max());
        assert_eq!(p.max, 20);
        assert_eq!(p.format, "ida");
        assert!(
            p.into_params()
                .iter()
                .all(|(k, _)| *k != "regex" && *k != "callers")
        );
    }

    #[test]
    fn find_function_by_string_emits_regex_flag() {
        let p = FindFunctionByString {
            value: "Daily|Timed".to_owned(),
            max: 20,
            format: "ida".to_owned(),
            regex: Some(true),
            callers: None,
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("value", "Daily|Timed".to_owned()),
                ("max", "20".to_owned()),
                ("format", "ida".to_owned()),
                ("regex", "1".to_owned()),
            ]
        );
    }

    #[test]
    fn find_function_by_string_emits_callers_flag() {
        let p = FindFunctionByString {
            value: "IsExecutionDone".to_owned(),
            max: 20,
            format: "ida".to_owned(),
            regex: None,
            callers: Some(true),
        };
        assert!(
            p.into_params()
                .iter()
                .any(|(k, v)| *k == "callers" && v == "1")
        );
    }

    #[test]
    fn decompile_emits_target_only_by_default() {
        let p = Decompile {
            target: "FUN_1400010a0".to_owned(),
            clean: None,
            offset: None,
            limit: None,
            grep: None,
            program: None,
        };
        assert_eq!(
            p.into_params(),
            vec![("target", "FUN_1400010a0".to_owned())]
        );
    }

    #[test]
    fn decompile_emits_clean_paging_grep_and_program() {
        let p = Decompile {
            target: "rva:0x2d202c".to_owned(),
            clean: Some("1".to_owned()),
            offset: Some(40),
            limit: Some(20),
            grep: Some("field_0x58".to_owned()),
            program: Some("alicia".to_owned()),
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("target", "rva:0x2d202c".to_owned()),
                ("clean", "1".to_owned()),
                ("offset", "40".to_owned()),
                ("limit", "20".to_owned()),
                ("grep", "field_0x58".to_owned()),
                ("program", "alicia".to_owned()),
            ]
        );
    }

    #[test]
    fn optional_params_are_omitted_when_absent() {
        let p = DebuggerListModules { trace: None };
        assert!(p.into_params().is_empty());
        let p = DebuggerListModules {
            trace: Some("t1".to_owned()),
        };
        assert_eq!(p.into_params(), vec![("trace", "t1".to_owned())]);
    }

    #[test]
    fn bool_flags_serialize_as_one_or_zero() {
        assert_eq!(flag(true), "1");
        assert_eq!(flag(false), "0");
    }

    #[test]
    fn tool_fail_is_a_visible_tool_error() {
        let client_err = tool_fail(BridgeError::Upstream {
            status: 400,
            body: "bad".into(),
        });
        let server_err = tool_fail(BridgeError::Upstream {
            status: 500,
            body: "boom".into(),
        });
        assert!(client_err.is_error.unwrap_or(false));
        assert!(server_err.is_error.unwrap_or(false));
        let client_text = format!("{client_err:?}");
        let server_text = format!("{server_err:?}");
        assert!(client_text.contains("bad"));
        assert!(server_text.contains("boom"));
    }

    #[test]
    fn advertises_2026_07_28_and_legacy_versions() {
        let server = dummy_server();
        let info = server.get_info();
        assert_eq!(info.protocol_version, ProtocolVersion::V_2026_07_28);
        let versions = server.supported_protocol_versions();
        assert!(versions.contains(&ProtocolVersion::V_2026_07_28));
        assert!(versions.contains(&ProtocolVersion::V_2025_11_25));
        assert!(versions.contains(&ProtocolVersion::V_2024_11_05));
        assert!(info.capabilities.completions.is_some());
    }

    #[test]
    fn complete_resource_uris_filters_prefix() {
        let hits = complete_resource_uris("ghidra://dro/");
        assert!(hits.iter().any(|u| u == "ghidra://dro/nebula-playbook"));
        assert!(hits.iter().all(|u| u.contains("ghidra://dro/")));
        assert!(complete_resource_uris("no-such-uri").is_empty());
    }

    #[test]
    fn complete_prompt_names_finds_workflows() {
        let hits = complete_prompt_names("raknet");
        assert!(hits.iter().any(|n| n == "analyze_raknet_handler"));
        assert!(!complete_prompt_names("").is_empty());
    }

    fn dummy_server() -> GhidraServer {
        GhidraServer::new(Url::parse("http://127.0.0.1:9/").unwrap(), 1, None).unwrap()
    }
}
