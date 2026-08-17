use crate::models::{SafetyLabelType, VfAction};
use crate::rules::{Rule, RuleContext};
use crate::models::high_risk_tags::contains_high_risk_tag;  // the helper above
use xai_visibility_filtering::models::{
    Action, DropReason, FilteredReason, SafetyResult, SafetyResultReason,
};

const HIGH_RISK_TAG_REASON: FilteredReason = FilteredReason::SafetyResult(SafetyResult {
    reason: Some(SafetyResultReason::NsfwHighPrecision), // or a new dedicated reason if enum allows
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
        // Need the post text – adjust field name to whatever the hydrated candidate exposes
        let text = &context.candidate().tweet_features.core.text;

        if !contains_high_risk_tag(text) {
            return VfAction::Allow;
        }

        if self.exempt_author && context.is_author_viewer() {
            return VfAction::Allow;
        }

        // Immediate penalty
        VfAction::Drop(HIGH_RISK_TAG_REASON.clone())
    }
}

pub const HIGH_RISK_TAG_DROP: HighRiskTagDropRule =
    HighRiskTagDropRule::new("HighRiskTagDropRule", true);
