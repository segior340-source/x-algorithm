//! High-risk tag (“killer-zone”) drop rule.
//!
//! Core objective (from issue #61):
//! The goal is NOT merely to hide or remove a specific tag.
//! Bad actors can rotate tags in seconds. The real goal is to:
//!
//! 1. Immediately reduce the visibility of posts that carry these
//!    high-risk tags (current implementation).
//! 2. Trigger alerts / signals so that the accounts posting or
//!    systematically engaging with this content can be reviewed.
//! 3. When content under these tags is later banned (high probability
//!    for this class of tags), the accounts that interacted with it
//!    (liked, reposted, replied, etc.) should receive ranking /
//!    credibility penalties and be placed under closer scrutiny
//!    (“watch” / negative reputation propagation).
//!
//! Current open-source limitation:
//! Only the post-level visibility drop is fully implementable here.
//! The full engagement → later-ban → user penalty pipeline and a
//! real-time watchlist are not completely exposed in this repository.
//! The comments document the intended direction so future work
//! (or internal systems) can continue from this point.
//!
//! Tags currently treated as high-risk signals:
//! teenageer, nolimits, momsonn, omegle

use crate::models::VfAction;
use crate::rules::{Rule, RuleContext};
use xai_visibility_filtering::models::{
    Action, DropReason, FilteredReason, SafetyResult, SafetyResultReason,
};

// Reuse an existing severe reason. This keeps the rule compatible
// with the current label system.
const HIGH_RISK_TAG_REASON: FilteredReason = FilteredReason::SafetyResult(SafetyResult {
    reason: Some(SafetyResultReason::NsfwHighPrecision),
    action: Action::Drop(DropReason {}),
});

/// Immediate drop for posts that contain any high-risk tag.
#[derive(Clone)]
pub struct HighRiskTagDropRule {
    name: &'static str,
    exempt_author: bool,   // usually true so the author can still see their own post
}

impl HighRiskTagDropRule {
    pub const fn new(name: &'static str, exempt_author: bool) -> Self {
        Self { name, exempt_author }
    }
}

impl Rule for HighRiskTagDropRule {
    fn name(&self) -> &'static str {
        self.name
    }

    fn evaluate(&self, context: &RuleContext<'_>) -> VfAction {
    let text = &context.candidate().tweet_features.core.text;
    let lower = text.to_lowercase();

    // Simple pattern: drop if any of these tags appear
let has_target_tag = lower.contains("teenageer")
    || lower.contains("nolimits")
    || lower.contains("momsonn")
    || lower.contains("omegle");

    if !has_target_tag {
        return VfAction::Allow;
    }

    if self.exempt_author && context.is_author_viewer() {
        return VfAction::Allow;
    }

    // Use the same severe label you already defined
    VfAction::Drop(HIGH_RISK_TAG_REASON.clone())
    }
}

pub const HIGH_RISK_TAG_DROP: HighRiskTagDropRule =
    HighRiskTagDropRule::new("HighRiskTagDropRule", true);
