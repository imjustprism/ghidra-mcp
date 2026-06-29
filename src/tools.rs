use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    handler::server::wrapper::Parameters,
    model::{
        AnnotateAble, CallToolResult, Content, GetPromptRequestParams, GetPromptResult,
        Implementation, ListPromptsResult, ListResourcesResult, PaginatedRequestParams,
        PromptMessage, PromptMessageRole, RawResource, ReadResourceRequestParams,
        ReadResourceResult, ResourceContents, ServerCapabilities, ServerInfo,
    },
    prompt, prompt_handler, prompt_router, schemars,
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::client::{BridgeError, GhidraHttp};

#[derive(Clone)]
pub struct GhidraServer {
    http: GhidraHttp,
}

fn ok_text(s: impl Into<String>) -> CallToolResult {
    CallToolResult::success(vec![Content::text(s.into())])
}

fn map_err(e: BridgeError) -> ErrorData {
    match &e {
        BridgeError::Upstream { status, .. } if (400..500).contains(status) => {
            ErrorData::invalid_params(e.to_string(), None)
        }
        BridgeError::Http(h) if h.is_connect() => ErrorData::internal_error(
            format!(
                "{e} — cannot reach the GhidraMCP plugin. Is Ghidra running with the \
                 ghidra-mcp extension enabled and a program open?"
            ),
            None,
        ),
        BridgeError::Http(h) if h.is_timeout() => ErrorData::internal_error(
            format!("{e} — request timed out. Raise --timeout-secs for long operations"),
            None,
        ),
        _ => ErrorData::internal_error(e.to_string(), None),
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

impl ToParams for NamePage {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        p.push(("name", self.name));
        p
    }
}

impl ToParams for CoverageReport {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        p.push(("path", self.path));
        p
    }
}

impl ToParams for CoverageDiff {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        p.push(("path_a", self.path_a));
        p.push(("path_b", self.path_b));
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

impl ToParams for RenameFunction {
    fn into_params(self) -> Params {
        vec![("oldName", self.old_name), ("newName", self.new_name)]
    }
}

impl ToParams for RenameData {
    fn into_params(self) -> Params {
        vec![("address", self.address), ("newName", self.new_name)]
    }
}

impl ToParams for RenameVariable {
    fn into_params(self) -> Params {
        vec![
            ("functionName", self.function_name),
            ("oldName", self.old_name),
            ("newName", self.new_name),
        ]
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

impl ToParams for ValueScan {
    fn into_params(self) -> Params {
        let mut p = vec![("value", self.value)];
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
        p
    }
}

impl ToParams for ScanNext {
    fn into_params(self) -> Params {
        let mut p = vec![("scan_id", self.scan_id)];
        if let Some(c) = self.comparator {
            p.push(("comparator", c));
        }
        if let Some(v) = self.value {
            p.push(("value", v));
        }
        p
    }
}

impl ToParams for ScanResults {
    fn into_params(self) -> Params {
        let mut p = vec![("scan_id", self.scan_id)];
        if let Some(l) = self.limit {
            p.push(("limit", l.to_string()));
        }
        p
    }
}

impl ToParams for ScanClose {
    fn into_params(self) -> Params {
        vec![("scan_id", self.scan_id)]
    }
}

impl ToParams for BatchItems {
    fn into_params(self) -> Params {
        vec![("items", self.items)]
    }
}

impl ToParams for RenameFunctionByAddress {
    fn into_params(self) -> Params {
        vec![
            ("function_address", self.function_address),
            ("new_name", self.new_name),
        ]
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

impl ToParams for SearchBytes {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        p.push(("pattern", self.pattern));
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

impl ToParams for FindString {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        p.push(("value", self.value));
        p
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

impl ToParams for EmuStep {
    fn into_params(self) -> Params {
        let mut p = vec![("emu_id", self.emu_id)];
        if let Some(c) = self.count {
            p.push(("count", c.to_string()));
        }
        p
    }
}

impl ToParams for EmuRunTo {
    fn into_params(self) -> Params {
        let mut p = vec![("emu_id", self.emu_id), ("stop", self.stop)];
        if let Some(m) = self.max_steps {
            p.push(("max_steps", m.to_string()));
        }
        p
    }
}

impl ToParams for EmuId {
    fn into_params(self) -> Params {
        vec![("emu_id", self.emu_id)]
    }
}

impl ToParams for EmuRegisters {
    fn into_params(self) -> Params {
        let mut p = vec![("emu_id", self.emu_id)];
        if self.full.unwrap_or(false) {
            p.push(("full", "1".to_string()));
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

impl ToParams for EmuSetRegister {
    fn into_params(self) -> Params {
        vec![
            ("emu_id", self.emu_id),
            ("register", self.register),
            ("value", self.value),
        ]
    }
}

impl ToParams for EmuReadMemory {
    fn into_params(self) -> Params {
        let mut p = vec![("emu_id", self.emu_id), ("address", self.address)];
        if let Some(l) = self.length {
            p.push(("length", l.to_string()));
        }
        p
    }
}

impl ToParams for EmuWriteMemory {
    fn into_params(self) -> Params {
        vec![
            ("emu_id", self.emu_id),
            ("address", self.address),
            ("hex", self.hex),
        ]
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

impl ToParams for CallgraphDot {
    fn into_params(self) -> Params {
        vec![("address", self.address), ("depth", self.depth.to_string())]
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

impl ToParams for FindSignature {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        p.push(("pattern", self.pattern));
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
        vec![
            ("value", self.value),
            ("max", self.max.to_string()),
            ("format", self.format),
        ]
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema, Default)]
pub struct Page {
    #[serde(default)]
    pub offset: u32,
    #[serde(default = "default_limit")]
    pub limit: u32,
    /// Output format: tsv (default), csv, json, or verbose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fmt: Option<String>,
    /// Target a specific open program by name or sha256 instead of the active one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
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
pub struct NamePage {
    pub name: String,
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
pub struct DecompileByName {
    pub name: String,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct RenameFunction {
    pub old_name: String,
    pub new_name: String,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct RenameData {
    pub address: String,
    pub new_name: String,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct RenameVariable {
    pub function_name: String,
    pub old_name: String,
    pub new_name: String,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct AddressComment {
    pub address: String,
    pub comment: String,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct RenameFunctionByAddress {
    pub function_address: String,
    pub new_name: String,
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
pub struct SearchBytes {
    pub pattern: String,
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
pub struct FindString {
    pub value: String,
    #[serde(flatten)]
    pub page: Page,
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
pub struct EmuStep {
    pub emu_id: String,
    #[serde(
        default,
        deserialize_with = "de_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub count: Option<u32>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct EmuRunTo {
    pub emu_id: String,
    pub stop: String,
    #[serde(
        default,
        deserialize_with = "de_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_steps: Option<u32>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct EmuId {
    pub emu_id: String,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct EmuRegisters {
    pub emu_id: String,
    #[serde(
        default,
        deserialize_with = "de_opt_bool",
        skip_serializing_if = "Option::is_none"
    )]
    pub full: Option<bool>,
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

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct EmuSetRegister {
    pub emu_id: String,
    pub register: String,
    pub value: String,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct EmuReadMemory {
    pub emu_id: String,
    pub address: String,
    #[serde(
        default,
        deserialize_with = "de_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub length: Option<u32>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct EmuWriteMemory {
    pub emu_id: String,
    pub address: String,
    pub hex: String,
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
    /// Output format: tsv (default), csv, json, or verbose.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fmt: Option<String>,
    /// Target a specific open program by name or sha256 instead of the active one.
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
pub struct CallgraphDot {
    pub address: String,
    #[serde(default = "default_callgraph_depth")]
    pub depth: u32,
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
const fn default_callgraph_depth() -> u32 {
    2
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
    /// "bytes" (default, wildcarded AOB) or "semantic" (emulation behavioral fingerprint).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct FindSignature {
    pub pattern: String,
    #[serde(flatten)]
    pub page: Page,
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
}
const fn default_ffbs_max() -> u32 {
    5
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
pub struct ValueScan {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub value_type: Option<String>,
    pub value: String,
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
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct ScanNext {
    pub scan_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comparator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct ScanResults {
    pub scan_id: String,
    #[serde(
        default,
        deserialize_with = "de_opt_u32",
        skip_serializing_if = "Option::is_none"
    )]
    pub limit: Option<u32>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct ScanClose {
    pub scan_id: String,
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
}

impl ToParams for DiffFunctions {
    fn into_params(self) -> Params {
        let mut p = vec![("address_a", self.address_a), ("address_b", self.address_b)];
        if let Some(b) = self.program_b {
            p.push(("program_b", b));
        }
        p
    }
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct CoverageReport {
    pub path: String,
    #[serde(flatten)]
    pub page: Page,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct CoverageDiff {
    pub path_a: String,
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
pub struct StructSetField {
    pub struct_name: String,
    pub offset: u32,
    #[serde(rename = "type")]
    pub data_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

impl ToParams for StructSetField {
    fn into_params(self) -> Params {
        let mut p = vec![
            ("struct", self.struct_name),
            ("offset", self.offset.to_string()),
            ("type", self.data_type),
        ];
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
pub struct StructDeleteField {
    pub struct_name: String,
    pub offset: u32,
}

impl ToParams for StructDeleteField {
    fn into_params(self) -> Params {
        vec![
            ("struct", self.struct_name),
            ("offset", self.offset.to_string()),
        ]
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
}

impl ToParams for XrefGraphArgs {
    fn into_params(self) -> Params {
        let mut p = vec![("address", self.address)];
        if let Some(m) = self.max {
            p.push(("max", m.to_string()));
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
}

impl ToParams for GraphMax {
    fn into_params(self) -> Params {
        self.max
            .map(|m| ("max", m.to_string()))
            .into_iter()
            .collect()
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
        self.http
            .get(path, &params.into_params())
            .await
            .map(ok_text)
            .map_err(map_err)
    }

    async fn get_bare(&self, path: &str) -> Result<CallToolResult, ErrorData> {
        self.http
            .get(path, NO_QUERY)
            .await
            .map(ok_text)
            .map_err(map_err)
    }

    async fn post(&self, path: &str, params: impl ToParams) -> Result<CallToolResult, ErrorData> {
        self.http
            .post_form(path, &params.into_params())
            .await
            .map(ok_text)
            .map_err(map_err)
    }

    async fn post_bare(&self, path: &str) -> Result<CallToolResult, ErrorData> {
        self.http
            .post_form(path, NO_QUERY)
            .await
            .map(ok_text)
            .map_err(map_err)
    }

    async fn post_raw(&self, path: &str, body: &str) -> Result<CallToolResult, ErrorData> {
        self.http
            .post_raw(path, body)
            .await
            .map(ok_text)
            .map_err(map_err)
    }
}

#[tool_router]
impl GhidraServer {
    #[tool(
        description = "List all function names in the program with pagination",
        annotations(read_only_hint = true)
    )]
    async fn list_methods(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("methods", p).await
    }

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
        description = "Decompile a specific function by name and return the decompiled C code",
        annotations(read_only_hint = true)
    )]
    async fn decompile_function(
        &self,
        Parameters(p): Parameters<DecompileByName>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post_raw("decompile", &p.name).await
    }

    #[tool(
        description = "Rename a function by its current name to a new user-defined name",
        annotations(destructive_hint = false)
    )]
    async fn rename_function(
        &self,
        Parameters(p): Parameters<RenameFunction>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("renameFunction", p).await
    }

    #[tool(
        description = "Rename a data label at the specified address",
        annotations(destructive_hint = false)
    )]
    async fn rename_data(
        &self,
        Parameters(p): Parameters<RenameData>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("renameData", p).await
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
        description = "Rename a local variable within a function",
        annotations(destructive_hint = false)
    )]
    async fn rename_variable(
        &self,
        Parameters(p): Parameters<RenameVariable>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("renameVariable", p).await
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
        description = "List all functions in the database",
        annotations(read_only_hint = true)
    )]
    async fn list_functions(&self) -> Result<CallToolResult, ErrorData> {
        self.get_bare("list_functions").await
    }

    #[tool(
        description = "Decompile the function at or containing the given address (an interior address resolves to its enclosing function)",
        annotations(read_only_hint = true)
    )]
    async fn decompile_function_by_address(
        &self,
        Parameters(p): Parameters<Address>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("decompile_function", p).await
    }

    #[tool(
        description = "Get assembly code (address: instruction; comment) for a function",
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
        description = "Rename a function by its address",
        annotations(destructive_hint = false)
    )]
    async fn rename_function_by_address(
        &self,
        Parameters(p): Parameters<RenameFunctionByAddress>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("rename_function_by_address", p).await
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
        description = "Get all references to the specified address (xref to)",
        annotations(read_only_hint = true)
    )]
    async fn get_xrefs_to(
        &self,
        Parameters(p): Parameters<AddressPage>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("xrefs_to", p).await
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
        description = "Structurally compare two functions and score their similarity 0-100. Compares instruction-mnemonic multisets (Jaccard), called-function-name sets, and size ratio. address_a is in the active program; address_b is in program_b if given (an open program by name/sha256, e.g. for cross-binary variant matching) else the active program. Returns the score plus the per-metric breakdown and each function's call set",
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
        description = "Get all references from the specified address (xref from)",
        annotations(read_only_hint = true)
    )]
    async fn get_xrefs_from(
        &self,
        Parameters(p): Parameters<AddressPage>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("xrefs_from", p).await
    }

    #[tool(
        description = "Get all references to the specified function by name. For imported/external functions, resolves call sites through the IAT (call qword [__imp_X]) by folding in references to the external symbol and its IAT slot — so Windows imports return their real call sites, not 0",
        annotations(read_only_hint = true)
    )]
    async fn get_function_xrefs(
        &self,
        Parameters(p): Parameters<NamePage>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("function_xrefs", p).await
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
        description = "Search program memory for a hex pattern. Use '??' for wildcard bytes. Returns matching addresses. For large images, paginate forward with the cursor: pass the address from the '# next_cursor:' footer as 'start' on the next call to resume the scan in O(1) instead of rescanning from the start",
        annotations(read_only_hint = true)
    )]
    async fn search_bytes(
        &self,
        Parameters(p): Parameters<SearchBytes>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.pattern.is_empty() {
            return Err(ErrorData::invalid_params("pattern is required", None));
        }
        self.get("search_bytes", p).await
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
        description = "Find defined string literals whose content contains the given substring (case-insensitive)",
        annotations(read_only_hint = true)
    )]
    async fn find_string(
        &self,
        Parameters(p): Parameters<FindString>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.value.is_empty() {
            return Err(ErrorData::invalid_params("value is required", None));
        }
        self.get("find_string", p).await
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
        description = "Start a persistent p-code emulator session at an address and return an emu_id. Unlike one-shot emulate, the session keeps register/memory state alive across calls so you can interactively step, inspect, and continue. stack sets the initial stack pointer (default 0x7fff0000). Pair with emu_step/emu_run_to/emu_registers/emu_read_memory and emu_close when done. Idle sessions are garbage-collected after 30 minutes"
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
        description = "Step a persistent emulator session forward by count instructions (default 1). Stops early on emulator halt. Returns instructions stepped and the new PC"
    )]
    async fn emu_step(
        &self,
        Parameters(p): Parameters<EmuStep>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("emu_step", p).await
    }

    #[tool(
        description = "Run a persistent emulator session until the program counter reaches stop or max_steps is exhausted (default 100000). Returns steps executed, stop reason, and the final PC"
    )]
    async fn emu_run_to(
        &self,
        Parameters(p): Parameters<EmuRunTo>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.stop.is_empty() {
            return Err(ErrorData::invalid_params("stop is required", None));
        }
        self.post("emu_run_to", p).await
    }

    #[tool(
        description = "Dump register values of a persistent emulator session. Shows the common GP/flags/segment registers by default; pass full=true for the entire bank (ZMM/K/ST/CR/DR/...)",
        annotations(read_only_hint = true)
    )]
    async fn emu_registers(
        &self,
        Parameters(p): Parameters<EmuRegisters>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("emu_registers", p).await
    }

    #[tool(
        description = "Set a register in a persistent emulator session. value accepts 0x-prefixed hex or decimal (negatives allowed). Use to seed function arguments or pointers before stepping"
    )]
    async fn emu_set_register(
        &self,
        Parameters(p): Parameters<EmuSetRegister>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("emu_set_register", p).await
    }

    #[tool(
        description = "Read length bytes (default 64) of emulator memory at an address in a persistent session. Reflects writes made by the emulated code",
        annotations(read_only_hint = true)
    )]
    async fn emu_read_memory(
        &self,
        Parameters(p): Parameters<EmuReadMemory>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("emu_read_memory", p).await
    }

    #[tool(
        description = "Write raw hex bytes into emulator memory at an address in a persistent session. Use to stage input buffers before running"
    )]
    async fn emu_write_memory(
        &self,
        Parameters(p): Parameters<EmuWriteMemory>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("emu_write_memory", p).await
    }

    #[tool(description = "Dispose a persistent emulator session and free its resources")]
    async fn emu_close(
        &self,
        Parameters(p): Parameters<EmuId>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("emu_close", p).await
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
        description = "Assemble x86/ARM/etc. assembly text to machine-code bytes at a given address (address matters for relative/RIP-relative encoding), via Ghidra's Assembler. Multiple instructions separated by newlines or ';' are assembled sequentially and the combined hex returned. Does NOT write — feed the bytes to patch_bytes to apply. The inverse of disassemble_function",
        annotations(read_only_hint = true)
    )]
    async fn assemble_code(
        &self,
        Parameters(p): Parameters<AssembleCode>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.address.trim().is_empty() || p.assembly.trim().is_empty() {
            return Err(ErrorData::invalid_params("address and assembly are required", None));
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
        description = "Emit a Graphviz DOT source for a call graph rooted at the function at address, BFS to the given depth",
        annotations(read_only_hint = true)
    )]
    async fn callgraph_dot(
        &self,
        Parameters(p): Parameters<CallgraphDot>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("callgraph_dot", p).await
    }

    #[tool(
        description = "Render a call graph as a Mermaid flowchart (renders inline in chat). direction: callees (default), callers, or both. depth and max_nodes bound the size",
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
        description = "Render a one-hop reference graph around an address as Mermaid: inbound references (callers/readers) and outbound references (call/jump/data targets), edges labeled by reference type. max caps the number of references shown, split fairly between the two directions (default 40, hard cap 200)",
        annotations(read_only_hint = true)
    )]
    async fn xref_graph(
        &self,
        Parameters(p): Parameters<XrefGraphArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("xref_graph", p).await
    }

    #[tool(
        description = "Render the same one-hop reference graph as xref_graph but as a self-contained, offline interactive HTML page (no external dependencies): inbound references on the left, outbound on the right, the center node highlighted, with mouse pan/zoom/drag and hover edge-highlighting. Save the output to a .html file and open it in a browser. max caps the references shown (default 40, hard cap 200)",
        annotations(read_only_hint = true)
    )]
    async fn xref_graph_html(
        &self,
        Parameters(p): Parameters<XrefGraphArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("xref_graph_html", p).await
    }

    #[tool(
        description = "Render the program's namespace/class hierarchy as a Mermaid top-down graph (parent namespace -> child). A module-altitude view of how the binary is organized. max caps the namespace count (default 80, hard cap 400)",
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
        description = "List defined strings with addresses. filter is case-insensitive substring by default; regex=true treats filter as a regex; xrefs=true emits one row per reference with from/function/ref_type columns",
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
        description = "Read raw live process memory at an absolute dynamic address — exact bytes, NO dereference. Works on the connector-less live_attach session (OpenProcess/ReadProcessMemory, no dbgeng) as well as a dbgeng trace. Use this (not read_pointer_path) to inspect bytes at a known address, e.g. walking heap/struct/map nodes. address is the absolute dynamic address; length is byte count",
        annotations(read_only_hint = true)
    )]
    async fn debugger_read_memory(
        &self,
        Parameters(p): Parameters<DebuggerReadMemory>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("debugger_read_memory", p).await
    }

    #[tool(
        description = "Resolve a multi-level pointer chain in the live target (CheatEngine-style); works connector-less (live_attach) or via a dbgeng trace. Rule: address accumulator starts at base; for EACH offset it dereferences the accumulator then adds the offset: final = [...[[base]+off0]+off1...]+offN. The final address itself is NOT dereferenced. offsets is comma-separated hex (with/without 0x; negatives ok), e.g. \"0x18,0x40,-0x8\". The output then ALSO dumps the bytes AT final (value_len bytes, or a default pointer-width word if omitted) as a convenience — that dump is one extra read of *final, not part of the chain. For a raw no-deref read at a known address use debugger_read_memory instead",
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
        description = "Execute arbitrary Lua INSIDE the live process's embedded Lua VM — for games that embed Lua (e.g. lua_tinker/Lua 5.1). DEFAULT (safe): installs a one-time detour on a per-frame engine tick (0x766620 for Alicia, the once-per-frame update called from the main message loop) and runs your script on the GAME'S OWN thread at frame start while the Lua VM is idle, via a shared mailbox — no extra thread, no reentrancy, no heap-lock deadlock. Hooking the idle frame tick (NOT lua_pcall, whose prologue is mid-call and corrupts the in-progress Lua stack) is what makes this safe. The hook auto-installs on first call (threads frozen + EIP-window-checked during the patch) and is removed on live_release. state = the lua_State (auto-detected via lua_find_state if omitted); fn = the dobuffer-style executor int(lua_State*, char* code, int len) (default 0x9e64d0 = lua_tinker::dobuffer for Alicia.exe). rc&0xff: 1=ok, 0=lua error; rc=-3 = the game has not called lua_pcall yet (bring it to a Lua-active screen). freeze=true selects the LEGACY UNSAFE CreateRemoteThread path which crashes a running VM — do not use it. For non-Alicia Lua 5.1 targets, override the hardcoded addresses: hook = the per-frame tick to detour (default 0x766620), and the C-API functions gettop/loadbuffer/pcall/settop (defaults 0x9c7c90/0x9c9c70/0x9c8aa0/0x9c7cb0) used by the eval cave. Use to call any in-game Lua: getters/setters, spawn, teleport, give items, run scripts",
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
        description = "Freeze a live memory address to a fixed value, re-written ~4x/sec like CheatEngine. hex is the bytes to hold at the address"
    )]
    async fn freeze_value(
        &self,
        Parameters(p): Parameters<PatchBytes>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.address.is_empty() {
            return Err(ErrorData::invalid_params("address is required", None));
        }
        if p.hex.is_empty() {
            return Err(ErrorData::invalid_params("hex is required", None));
        }
        self.post("freeze_value", p).await
    }

    #[tool(
        description = "Stop freezing a previously frozen address",
        annotations(destructive_hint = false)
    )]
    async fn unfreeze_value(
        &self,
        Parameters(p): Parameters<Address>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.address.is_empty() {
            return Err(ErrorData::invalid_params("address is required", None));
        }
        self.post("unfreeze_value", p).await
    }

    #[tool(
        description = "List currently frozen addresses and the values held",
        annotations(read_only_hint = true)
    )]
    async fn list_frozen(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("list_frozen", p).await
    }

    #[tool(
        description = "CheatEngine-style first scan of live process memory for a value. type: i8|i16|i32|i64|f32|f64|string|bytes (default i32). Scans heap/data regions and skips loaded modules by default (all=true scans everything, slower; exclude_modules=true forces module skipping). tolerance (f32/f64 only) matches values within +/- tolerance of the target — essential for floats. max_mb raises the scan budget (default 1024, cap 8192). Async: returns a scan_id immediately; poll scan_results for status=running/done, then refine with next_scan",
        annotations(read_only_hint = true)
    )]
    async fn value_scan(
        &self,
        Parameters(p): Parameters<ValueScan>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.value.is_empty() {
            return Err(ErrorData::invalid_params("value is required", None));
        }
        self.get("value_scan", p).await
    }

    #[tool(
        description = "Refine a previous scan by re-reading live memory. comparator: exact|changed|unchanged|increased|decreased (exact/value needs value). Narrows the candidate set",
        annotations(read_only_hint = true)
    )]
    async fn next_scan(
        &self,
        Parameters(p): Parameters<ScanNext>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.scan_id.is_empty() {
            return Err(ErrorData::invalid_params("scan_id is required", None));
        }
        self.post("next_scan", p).await
    }

    #[tool(
        description = "Close a finished scan session and free its candidate list. Call when done refining",
        annotations(destructive_hint = false)
    )]
    async fn scan_close(
        &self,
        Parameters(p): Parameters<ScanClose>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.scan_id.is_empty() {
            return Err(ErrorData::invalid_params("scan_id is required", None));
        }
        self.post("scan_close", p).await
    }

    #[tool(
        description = "List remaining candidates of a scan with their dynamic + static addresses and current values",
        annotations(read_only_hint = true)
    )]
    async fn scan_results(
        &self,
        Parameters(p): Parameters<ScanResults>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.scan_id.is_empty() {
            return Err(ErrorData::invalid_params("scan_id is required", None));
        }
        self.get("scan_results", p).await
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
        description = "Decompile a function and strip cosmetic noise: drop (int)/(uint)/(longlong) casts on iVar/uVar/param_/local_ identifiers, remove decompiler WARNING comment blocks, collapse blank lines. Anything not matching these templates passes through unchanged",
        annotations(read_only_hint = true)
    )]
    async fn decompile_minimal(
        &self,
        Parameters(p): Parameters<Address>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("decompile_minimal", p).await
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
        description = "Scan program memory for a byte pattern and return matching addresses. Accepts any common dialect: IDA/x64dbg/Cheat-Engine token form ('48 8B ?? E8 ? ? ? ?', spaced or contiguous, ? or ?? wildcards) or code+mask form ('\\x48\\x8B\\x00' with mask 'xx?'). Paginated",
        annotations(read_only_hint = true)
    )]
    async fn find_signature(
        &self,
        Parameters(p): Parameters<FindSignature>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.pattern.is_empty() {
            return Err(ErrorData::invalid_params("pattern is required", None));
        }
        self.get("find_signature", p).await
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
        description = "One-call context pack for a function at an address: metadata + signature, cleaned decompiled C, callers, callees, and referenced strings, in one response. The fastest way to load everything needed to understand and name a function. limit caps each list section",
        annotations(read_only_hint = true)
    )]
    async fn function_summary_bundle(
        &self,
        Parameters(p): Parameters<AddressPage>,
    ) -> Result<CallToolResult, ErrorData> {
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
        description = "Extract indicators of compromise from defined strings: URLs, IPv4 addresses, emails, registry keys, Windows/UNC file paths, GUIDs, and crypto-wallet (BTC) addresses, each with its category and string address. Fast malware-triage convenience over the string table",
        annotations(read_only_hint = true)
    )]
    async fn extract_iocs(
        &self,
        Parameters(p): Parameters<Page>,
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
        description = "Map an execution-coverage file to functions and report which were hit. path points to a text file of executed addresses (one hex address per line; '0x' optional, a trailing space-separated field like a hit count is ignored, '#'/';' comments skipped) under the allow-listed File IO Directory. Returns covered/total function count, percentage, and the covered function list. Use to triage which code a fuzzer/trace exercised",
        annotations(read_only_hint = true)
    )]
    async fn coverage_report(
        &self,
        Parameters(p): Parameters<CoverageReport>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.path.is_empty() {
            return Err(ErrorData::invalid_params("path is required", None));
        }
        self.get("coverage_report", p).await
    }

    #[tool(
        description = "Block-level coverage from an execution-trace file (same address-list format as coverage_report). Maps each executed address to its basic block, then reports, per hit function, how many of its basic blocks were covered (blocks_covered/blocks_total + pct). Finer-grained than coverage_report — shows how deeply each function was exercised, for path/fuzzing triage",
        annotations(read_only_hint = true)
    )]
    async fn trace_to_coverage(
        &self,
        Parameters(p): Parameters<CoverageReport>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.path.is_empty() {
            return Err(ErrorData::invalid_params("path is required", None));
        }
        self.get("trace_to_coverage", p).await
    }

    #[tool(
        description = "Diff two execution-coverage files (same address-list format as coverage_report) at function granularity: reports functions covered only by A, only by B, and the shared count. Use to see what a new input/trace reached that another didn't",
        annotations(read_only_hint = true)
    )]
    async fn coverage_diff(
        &self,
        Parameters(p): Parameters<CoverageDiff>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.path_a.is_empty() || p.path_b.is_empty() {
            return Err(ErrorData::invalid_params(
                "path_a and path_b are required",
                None,
            ));
        }
        self.get("coverage_diff", p).await
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
        description = "Compute a structural hash of the function at an address, independent of addresses and immediate values: a mnemonic_hash (instruction opcodes only) and a shape_hash (opcodes + operand count per instruction). Hashed over the body in address order, so it is an exact-match fingerprint best for deduping identical functions and matching the same function across builds with stable layout (not a fuzzy cross-compiler matcher). Matching hashes imply structurally identical code",
        annotations(read_only_hint = true)
    )]
    async fn function_hash(
        &self,
        Parameters(p): Parameters<Address>,
    ) -> Result<CallToolResult, ErrorData> {
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
        description = "Infer a struct layout from how a pointer variable is used. Decompiles the function, follows every load/store through the named pointer variable (a parameter or local), AND captures base+const sub-pointers (&ptr->field) passed by address into helper/constructor calls — the common C++ pattern the raw recovery misses — adding them as ref_arg fields. Creates a new struct data type whose fields match the accessed offsets, sizes, and types. Returns the proposed layout (offset/length/type/field). Great for recovering an unknown structure from the code that touches it",
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
        description = "Locate functions by a string they reference: finds the string, follows cross-references to the containing function, and emits each function's name, entry address, the xref site, and a unique signature for the entry. The fastest path from a known string to a function + a reusable signature. format=ida|code",
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
        description = "Set a field in an existing structure at a byte offset. mode=replace (default) overwrites whatever occupies the offset; mode=insert shifts later fields down. type accepts builtins or any defined type name. name is optional",
        annotations(destructive_hint = false)
    )]
    async fn struct_set_field(
        &self,
        Parameters(p): Parameters<StructSetField>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.struct_name.is_empty() {
            return Err(ErrorData::invalid_params("struct_name is required", None));
        }
        self.post("struct_set_field", p).await
    }

    #[tool(
        description = "Delete the field at a byte offset in an existing structure, replacing it with undefined space",
        annotations(destructive_hint = false)
    )]
    async fn struct_delete_field(
        &self,
        Parameters(p): Parameters<StructDeleteField>,
    ) -> Result<CallToolResult, ErrorData> {
        if p.struct_name.is_empty() {
            return Err(ErrorData::invalid_params("struct_name is required", None));
        }
        self.post("struct_delete_field", p).await
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
    vec![PromptMessage::new_text(
        PromptMessageRole::User,
        text.to_owned(),
    )]
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
             3. list_entry_points, then decompile_minimal each entry.\n\
             4. high_entropy_regions — packed/encrypted zones.\n\
             5. Capability triage: find_anti_debug, find_anti_vm, find_api_hashes, find_crypto_constants, find_syscalls.\n\
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
             3. find_encoded_strings + find_stack_strings — hidden strings/IOCs.\n\
             4. find_crypto_constants — AES/SHA/MD5/CRC (ransomware/packer crypto).\n\
             5. find_syscalls — direct-syscall / EDR evasion.\n\
             6. high_entropy_regions + cfg_obfuscation_score on suspicious functions.\n\
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
             1. find_check_function — locate the password/key check.\n\
             2. function_summary_bundle on it; identify the comparison(s).\n\
             3. extract_constraints — collect cmp/branch constraints toward the success path.\n\
             4. find_magic_constants — embedded comparison values.\n\
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
}

type Resource = (&'static str, &'static str, &'static str);

const RESOURCES: &[Resource] = &[
    ("ghidra://program/info", "Program info", "program_info"),
    (
        "ghidra://program/current-function",
        "Current function",
        "get_current_function",
    ),
    (
        "ghidra://program/current-address",
        "Current address",
        "get_current_address",
    ),
    (
        "ghidra://debugger/status",
        "Debugger status (live)",
        "debugger_status",
    ),
];

#[tool_handler]
#[prompt_handler]
impl ServerHandler for GhidraServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_prompts()
                .enable_resources()
                .build(),
        )
        .with_server_info(Implementation::new("ghidra-mcp", env!("CARGO_PKG_VERSION")))
        .with_instructions(
            "Rust-based MCP bridge to the GhidraMCP HTTP plugin. Tools decompile, disassemble, \
             search, and annotate; prompts give guided RE workflows; resources expose live \
             program and debugger state."
                .to_owned(),
        )
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        let resources = RESOURCES
            .iter()
            .map(|(uri, name, _)| RawResource::new(*uri, *name).no_annotation())
            .collect();
        Ok(ListResourcesResult::with_all_items(resources))
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, ErrorData> {
        let Some((uri, _, endpoint)) = RESOURCES.iter().find(|(uri, ..)| *uri == request.uri)
        else {
            return Err(ErrorData::resource_not_found(
                format!("unknown resource: {}", request.uri),
                None,
            ));
        };
        let body = self.http.get(endpoint, NO_QUERY).await.map_err(map_err)?;
        Ok(ReadResourceResult::new(vec![ResourceContents::text(
            body, *uri,
        )]))
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
            program: Some("Alicia.exe".to_owned()),
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
                ("program", "Alicia.exe".to_owned()),
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
        assert!(names.iter().any(|n| n == "list_methods"));
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
        let p = CoverageReport {
            path: "cov.txt".to_owned(),
            page: Page {
                offset: 0,
                limit: 100,
                fmt: None,
                program: None,
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
        let p = CoverageDiff {
            path_a: "a.txt".to_owned(),
            path_b: "b.txt".to_owned(),
            page: Page {
                offset: 0,
                limit: 100,
                fmt: None,
                program: None,
            },
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("offset", "0".to_owned()),
                ("limit", "100".to_owned()),
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
    fn emu_run_to_emits_id_stop_and_optional_max() {
        let p = EmuRunTo {
            emu_id: "emu3".to_owned(),
            stop: "0x401050".to_owned(),
            max_steps: None,
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("emu_id", "emu3".to_owned()),
                ("stop", "0x401050".to_owned())
            ]
        );
    }

    #[test]
    fn emu_set_register_emits_all_fields() {
        let p = EmuSetRegister {
            emu_id: "emu1".to_owned(),
            register: "RDI".to_owned(),
            value: "0x10".to_owned(),
        };
        assert_eq!(
            p.into_params(),
            vec![
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
    fn search_bytes_appends_start_cursor_when_set() {
        let p = SearchBytes {
            pattern: "48 8B ??".to_owned(),
            start: Some("0x401234".to_owned()),
            page: Page {
                offset: 0,
                limit: 20,
                fmt: None,
                program: None,
            },
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("offset", "0".to_owned()),
                ("limit", "20".to_owned()),
                ("pattern", "48 8B ??".to_owned()),
                ("start", "0x401234".to_owned()),
            ]
        );
    }

    #[test]
    fn rename_function_uses_camelcase_wire_keys() {
        let p = RenameFunction {
            old_name: "sub_401000".to_owned(),
            new_name: "decode".to_owned(),
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("oldName", "sub_401000".to_owned()),
                ("newName", "decode".to_owned()),
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
    fn find_signature_composes_page_then_pattern() {
        let p = FindSignature {
            pattern: "48 8B ?? E8".to_owned(),
            page: Page {
                offset: 0,
                limit: 20,
                fmt: None,
                program: None,
            },
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("offset", "0".to_owned()),
                ("limit", "20".to_owned()),
                ("pattern", "48 8B ?? E8".to_owned()),
            ]
        );
    }

    #[test]
    fn find_function_by_string_defaults() {
        let p: FindFunctionByString = serde_json::from_str(r#"{"value":"licen"}"#).unwrap();
        assert_eq!(p.max, default_ffbs_max());
        assert_eq!(p.format, "ida");
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
    fn map_err_classifies_4xx_as_invalid_params() {
        let client_err = map_err(BridgeError::Upstream {
            status: 400,
            body: "bad".into(),
        });
        let server_err = map_err(BridgeError::Upstream {
            status: 500,
            body: "boom".into(),
        });
        assert_eq!(client_err.code, ErrorData::invalid_params("bad", None).code);
        assert_eq!(
            server_err.code,
            ErrorData::internal_error("boom", None).code
        );
        assert_ne!(client_err.code, server_err.code);
    }
}
