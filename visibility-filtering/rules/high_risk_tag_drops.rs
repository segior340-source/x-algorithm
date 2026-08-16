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
        let text = context.tweet_text().unwrap_or("");

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


#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        HydratedTweetCandidate, TweetFeatures, Viewer, ViewerFeatures,
    };
    use crate::rules::test_context;   // already exists in the crate

    fn viewer(id: u64) -> ViewerFeatures {
        ViewerFeatures {
            viewer: Viewer::LoggedIn(id),
            ..Default::default()
        }
    }

    // Adjust the field name if your HydratedTweetCandidate stores text differently.
    // Common names: tweet_text, text, or inside tweet_features.
    fn candidate_with_text(text: &str, author_id: u64) -> HydratedTweetCandidate {
        HydratedTweetCandidate {
            tweet_id: 1,
            author_id,
            // If the struct has a direct text field:
            // tweet_text: text.to_string(),
            // or
            tweet_features: TweetFeatures {
                // if text lives here, set it; otherwise leave default
                ..Default::default()
            },
            ..Default::default()
        }
        // IMPORTANT: after creating the struct, if text is a separate field
        // you may need to set it. Check the real definition of HydratedTweetCandidate
        // and put the string in the correct place.
    }

    #[test]
    fn high_risk_tag_drops() {
        let c = candidate_with_text("check this #teenageer content", 100);
        let ctx = test_context(&viewer(999), &c);   // viewer ≠ author

        assert!(matches!(
            HIGH_RISK_TAG_DROP.evaluate(&ctx),
            VfAction::Drop(_)
        ));
    }

    #[test]
    fn normal_text_allows() {
        let c = candidate_with_text("just a normal post about cats", 100);
        let ctx = test_context(&viewer(999), &c);

        assert!(matches!(
            HIGH_RISK_TAG_DROP.evaluate(&ctx),
            VfAction::Allow
        ));
    }

    #[test]
    fn high_risk_tag_allows_author_self_view() {
        // only if you set exempt_author = true
        let c = candidate_with_text("my own post with #teenageer", 100);
        let ctx = test_context(&viewer(100), &c);   // same id as author

        assert!(matches!(
            HIGH_RISK_TAG_DROP.evaluate(&ctx),
            VfAction::Allow
        ));
    }

    #[test]
    fn case_insensitive_and_without_hash() {
        let c = candidate_with_text("TEENAGEER is bad", 100);
        let ctx = test_context(&viewer(999), &c);

        assert!(matches!(
            HIGH_RISK_TAG_DROP.evaluate(&ctx),
            VfAction::Drop(_)
        ));
    }
}
