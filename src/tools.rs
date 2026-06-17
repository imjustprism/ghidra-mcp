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

trait ToParams {
    fn into_params(self) -> Params;
}

fn flag(value: bool) -> String {
    if value { "1" } else { "0" }.to_owned()
}

impl ToParams for Page {
    fn into_params(self) -> Params {
        vec![
            ("offset", self.offset.to_string()),
            ("limit", self.limit.to_string()),
        ]
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

impl ToParams for ValueScan {
    fn into_params(self) -> Params {
        let mut p = vec![("value", self.value)];
        if let Some(t) = self.value_type {
            p.push(("type", t));
        }
        if self.all.unwrap_or(false) {
            p.push(("all", "1".to_string()));
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
        vec![("address", self.address), ("hex", self.hex)]
    }
}

impl ToParams for SearchBytes {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        p.push(("pattern", self.pattern));
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
        vec![
            ("address", self.address),
            ("max_len", self.max_len.to_string()),
            ("format", self.format),
        ]
    }
}

impl ToParams for FindSignature {
    fn into_params(self) -> Params {
        let mut p = self.page.into_params();
        p.push(("pattern", self.pattern));
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
}
const fn default_limit() -> u32 {
    100
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct Address {
    pub address: String,
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
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct SearchBytes {
    pub pattern: String,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depth: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_nodes: Option<u32>,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct StructDiagramArgs {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    pub max_len: u32,
    #[serde(default = "default_format")]
    pub format: String,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
pub struct FindSignature {
    pub pattern: String,
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
pub struct ValueScan {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub value_type: Option<String>,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub all: Option<bool>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
pub struct SetVariables {
    pub function_address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prototype: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variables: Option<Vec<VariableEdit>>,
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

const NO_QUERY: &[(); 0] = &[];

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
        description = "List imported symbols with pagination",
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
        description = "Decompile a function at the given address",
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
        description = "Get all references to the specified function by name",
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
        description = "Search program memory for a hex pattern. Use '??' for wildcard bytes. Returns matching addresses",
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
        description = "Patch program memory with raw hex bytes at the given address. Modifies Ghidra's program image only"
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
        description = "Scan imports and functions for classic anti-debug / anti-tamper indicators (IsDebuggerPresent, NtQueryInformationProcess, RDTSC probes, etc.)",
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
        description = "Heuristic vtable scan: scan .rdata/.data.rel.ro for runs of 3+ consecutive pointers into .text. Reports (address, size, first_func_address, count). Paginated via offset/limit",
        annotations(read_only_hint = true)
    )]
    async fn vtable_scan(
        &self,
        Parameters(p): Parameters<Page>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("vtable_scan", p).await
    }

    #[tool(
        description = "List all defined strings in the program with their addresses",
        annotations(read_only_hint = true)
    )]
    async fn list_strings(
        &self,
        Parameters(p): Parameters<ListStrings>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("strings", p).await
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
        description = "Register name/value pairs for the current frame of the given thread (optional)",
        annotations(read_only_hint = true)
    )]
    async fn debugger_registers(
        &self,
        Parameters(p): Parameters<DebuggerThreadFilter>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("debugger_registers", p).await
    }

    #[tool(
        description = "Read live target memory (not static program image) at a dynamic address",
        annotations(read_only_hint = true)
    )]
    async fn debugger_read_memory(
        &self,
        Parameters(p): Parameters<DebuggerReadMemory>,
    ) -> Result<CallToolResult, ErrorData> {
        self.get("debugger_read_memory", p).await
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
        description = "Start a live debug session from the MCP (no Ghidra GUI needed). offer is a configName from debugger_list_offers; args is comma-separated key=value parameter overrides (e.g. the PID for a dbgeng attach offer)"
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
        description = "CheatEngine-style first scan of live process memory for a value. type: i8|i16|i32|i64|f32|f64|string|bytes (default i32). Scans heap/data regions and skips loaded modules by default (all=true scans everything, slower). Async: returns a scan_id immediately; poll scan_results for status=running/done, then refine with next_scan",
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
        description = "Scan executable memory for magic-constant immediate operands used in CMP/MOV/ADD/SUB/XOR/AND/OR/IMUL/TEST/LEA/SHL/SHR/SAR/ROL/ROR/PUSH. Filters small integers (0..4, 8, 16, ...) and full-ones masks. Optional min/max (hex via 0x) narrow the range",
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
        description = "Detect arithmetic idioms in a function: unsigned divide-by-constant magic (reciprocal form for divisors 3..255), MOVSXD sign-extend-drop, and IMUL+SUB pair matching x - k*(x/k) = x %% k. With apply=true, the match is written as an EOL comment on the instruction",
        annotations(destructive_hint = false)
    )]
    async fn idiom_simplifier(
        &self,
        Parameters(p): Parameters<IdiomSimplifierInput>,
    ) -> Result<CallToolResult, ErrorData> {
        self.post("idiom_simplifier", p).await
    }

    #[tool(
        description = "Generate a unique wildcarded byte signature (AOB pattern) for the code at an address. Walks instructions from the address, keeps opcode/modrm bytes, wildcards address/relative/RIP-relative operands (keeps stable immediates), extends until the pattern is globally unique, and trims trailing wildcards. format=ida ('48 8B ?? E8 ? ? ? ?') or code ('\\x48\\x8B\\x00' + mask). Output starts with a header line reporting byte length, wildcard count, match count, and whether it is unique",
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
        description = "Apply many data types in one call and one transaction. items is a JSON array of {address, type, clear?} (clear defaults to 1). Best-effort: a failing item is reported but does not roll back the others. Returns a per-item ok/fail report",
        annotations(destructive_hint = false)
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
    fn page_into_params_emits_offset_and_limit() {
        let p = Page {
            offset: 5,
            limit: 9,
        };
        assert_eq!(
            p.into_params(),
            vec![("offset", "5".to_owned()), ("limit", "9".to_owned())]
        );
    }

    #[test]
    fn address_page_composes_page_params_then_address() {
        let p = AddressPage {
            address: "0x401000".to_owned(),
            page: Page {
                offset: 0,
                limit: 50,
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
            max_len: 64,
            format: "ida".to_owned(),
        };
        assert_eq!(
            p.into_params(),
            vec![
                ("address", "0x401000".to_owned()),
                ("max_len", "64".to_owned()),
                ("format", "ida".to_owned()),
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
