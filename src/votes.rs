use std::collections::BTreeMap;

use crate::{EvidenceAssertion, EvidenceV1, ExpectedReadback, ObservedState};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Vote {
    Match,
    Contradict,
    Abstain,
    Conflict,
}

pub(crate) fn readback(
    expectation: &ExpectedReadback,
    evidence: &[(EvidenceV1, String)],
) -> BTreeMap<String, Vote> {
    let mut votes = BTreeMap::new();
    for (value, group) in evidence {
        let vote = classify(expectation, value);
        votes
            .entry(group.clone())
            .and_modify(|current| *current = merge(*current, vote))
            .or_insert(vote);
    }
    votes
}

pub(crate) fn counts(votes: &BTreeMap<String, Vote>) -> (usize, usize) {
    (
        votes.values().filter(|vote| **vote == Vote::Match).count(),
        votes
            .values()
            .filter(|vote| **vote == Vote::Contradict)
            .count(),
    )
}

fn classify(expectation: &ExpectedReadback, evidence: &EvidenceV1) -> Vote {
    let EvidenceAssertion::State(state) = evidence.assertion else {
        return Vote::Abstain;
    };
    if state != expectation.expected_state {
        return if state == ObservedState::Indeterminate {
            Vote::Abstain
        } else {
            Vote::Contradict
        };
    }
    if evidence.resource_version.as_deref() == Some(expectation.expected_resource_version.as_str())
        && evidence
            .fence
            .is_some_and(|value| value >= expectation.minimum_fence)
    {
        Vote::Match
    } else {
        Vote::Abstain
    }
}

fn merge(left: Vote, right: Vote) -> Vote {
    match (left, right) {
        (Vote::Abstain, value) | (value, Vote::Abstain) => value,
        (left, right) if left == right => left,
        _ => Vote::Conflict,
    }
}
