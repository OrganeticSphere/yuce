//! Structured kernel errors. Every rejection carries the value the kernel computed
//! (`expected_by_kernel`) and the repair obligation for the agent, so a failing line can be
//! fixed in one step without regenerating the accepted prefix.

use serde_json::{json, Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    BadJson,
    MissingField,
    BadField,
    UnknownOp,
    SeqMismatch,
    DuplicateLocalId,
    UnknownLocalId,
    UnknownDoc,
    QuoteNotFoundInBytes,
    AmbiguousQuoteSpan,
    EvidenceRevoked,
    UnknownEntity,
    AmbiguousEntity,
    UnknownPredicate,
    TypeMismatch,
    UnknownRule,
    BadPolarity,
    BadInterval,
    NoEvidence,
    EvidenceNotActive,
    NotAClaim,
    NotAnEvidence,
    ArityMismatch,
    PremisePredicateMismatch,
    PremiseUnsupported,
    PremiseConflicting,
    JoinViolation,
    CtxMismatch,
    EmptyIntervalIntersection,
    IntervalMismatch,
    HeadMismatch,
    OrPremisesInconsistent,
    AlreadyRevoked,
    DocNotUtf8,
    QuoteTooFragmented,
    LiteralNotAllowed,
}

impl Code {
    pub fn as_str(self) -> &'static str {
        match self {
            Code::BadJson => "BAD_JSON",
            Code::MissingField => "MISSING_FIELD",
            Code::BadField => "BAD_FIELD",
            Code::UnknownOp => "UNKNOWN_OP",
            Code::SeqMismatch => "SEQ_MISMATCH",
            Code::DuplicateLocalId => "DUPLICATE_LOCAL_ID",
            Code::UnknownLocalId => "UNKNOWN_LOCAL_ID",
            Code::UnknownDoc => "UNKNOWN_DOC",
            Code::QuoteNotFoundInBytes => "QUOTE_NOT_FOUND_IN_BYTES",
            Code::AmbiguousQuoteSpan => "AMBIGUOUS_QUOTE_SPAN",
            Code::EvidenceRevoked => "EVIDENCE_REVOKED",
            Code::UnknownEntity => "UNKNOWN_ENTITY",
            Code::AmbiguousEntity => "AMBIGUOUS_ENTITY",
            Code::UnknownPredicate => "UNKNOWN_PREDICATE",
            Code::TypeMismatch => "TYPE_MISMATCH",
            Code::UnknownRule => "UNKNOWN_RULE",
            Code::BadPolarity => "BAD_POLARITY",
            Code::BadInterval => "BAD_INTERVAL",
            Code::NoEvidence => "NO_EVIDENCE",
            Code::EvidenceNotActive => "EVIDENCE_NOT_ACTIVE",
            Code::NotAClaim => "NOT_A_CLAIM",
            Code::NotAnEvidence => "NOT_AN_EVIDENCE",
            Code::ArityMismatch => "ARITY_MISMATCH",
            Code::PremisePredicateMismatch => "PREMISE_PREDICATE_MISMATCH",
            Code::PremiseUnsupported => "PREMISE_UNSUPPORTED",
            Code::PremiseConflicting => "PREMISE_CONFLICTING",
            Code::JoinViolation => "JOIN_VIOLATION",
            Code::CtxMismatch => "CTX_MISMATCH",
            Code::EmptyIntervalIntersection => "EMPTY_INTERVAL_INTERSECTION",
            Code::IntervalMismatch => "INTERVAL_MISMATCH",
            Code::HeadMismatch => "HEAD_MISMATCH",
            Code::OrPremisesInconsistent => "OR_PREMISES_INCONSISTENT",
            Code::AlreadyRevoked => "ALREADY_REVOKED",
            Code::DocNotUtf8 => "DOC_NOT_UTF8",
            Code::QuoteTooFragmented => "QUOTE_TOO_FRAGMENTED",
            Code::LiteralNotAllowed => "LITERAL_NOT_ALLOWED",
        }
    }
}

#[derive(Debug, Clone)]
pub struct KernelError {
    pub code: Code,
    pub seq: Option<u64>,
    pub field: Option<String>,
    pub message: String,
    pub expected_by_kernel: Value,
    pub obligation: Value,
}

impl KernelError {
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        KernelError { code, seq: None, field: None, message: message.into(), expected_by_kernel: Value::Null, obligation: Value::Null }
    }

    pub fn field(mut self, f: &str) -> Self {
        self.field = Some(f.to_string());
        self
    }

    pub fn expected(mut self, v: Value) -> Self {
        self.expected_by_kernel = v;
        self
    }

    pub fn obligation(mut self, v: Value) -> Self {
        self.obligation = v;
        self
    }

    pub fn with_seq(mut self, seq: u64) -> Self {
        self.seq = Some(seq);
        self
    }

    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("status".into(), json!("error"));
        if let Some(s) = self.seq {
            m.insert("seq".into(), json!(s));
        }
        m.insert("code".into(), json!(self.code.as_str()));
        if let Some(f) = &self.field {
            m.insert("field".into(), json!(f));
        }
        m.insert("message".into(), json!(self.message));
        m.insert("expected_by_kernel".into(), self.expected_by_kernel.clone());
        m.insert("obligation".into(), self.obligation.clone());
        Value::Object(m)
    }
}

impl std::fmt::Display for KernelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for KernelError {}

pub type KResult<T> = Result<T, KernelError>;
