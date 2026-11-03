export const NO_TECHNIQUE_EVIDENCE = 'No technique-specific evidence available. This candidate requires analyst review.';
export const DEFAULT_RETRIEVAL_REASON = 'Ranked by semantic similarity between the stage investigation query and ATT&CK technique text.';

const stringIds = values => Array.isArray(values)
  ? [...new Set(values.filter(value => typeof value === 'string' && value.trim()))]
  : [];

function normalizeCandidate(candidate = {}) {
  const sourceEvidence = candidate.candidate_evidence && typeof candidate.candidate_evidence === 'object'
    ? candidate.candidate_evidence
    : {};
  const flowIds = stringIds(sourceEvidence.flow_ids);
  const eventIds = stringIds(sourceEvidence.event_ids);
  const linked = flowIds.length > 0 || eventIds.length > 0;
  const similarityValue = candidate.retrieval_similarity ??
    (candidate.score_semantics === 'cosine_similarity' ? candidate.score : undefined);
  const retrievalSimilarity = similarityValue !== null && similarityValue !== undefined &&
    similarityValue !== '' && Number.isFinite(Number(similarityValue))
    ? Number(similarityValue)
    : null;
  const {
    evidence_flow_ids: _stageFlowIds,
    evidence_ids: _stageEvidenceIds,
    evidence_basis: _stageEvidenceBasis,
    score: _ambiguousScore,
    assessment: _legacyAssessment,
    mapping_status: _legacyMappingStatus,
    ...preserved
  } = candidate;

  return {
    ...preserved,
    retrieval_similarity: retrievalSimilarity,
    score_semantics: candidate.score_semantics === 'cosine_similarity' ? 'cosine_similarity' : null,
    retrieval_reason: typeof candidate.retrieval_reason === 'string' && candidate.retrieval_reason.trim()
      ? candidate.retrieval_reason
      : DEFAULT_RETRIEVAL_REASON,
    candidate_status: linked ? 'evidence_linked_candidate' : 'retrieved_candidate',
    evidence_status: linked ? 'candidate_specific' : 'none_available',
    review_status: 'not_reviewed',
    assessment: linked
      ? (typeof sourceEvidence.reason === 'string' && sourceEvidence.reason.trim()
        ? sourceEvidence.reason
        : 'Candidate-specific references are available; analyst review is required.')
      : NO_TECHNIQUE_EVIDENCE,
    candidate_evidence: {
      flow_ids: flowIds,
      event_ids: eventIds,
      reason: linked && typeof sourceEvidence.reason === 'string' && sourceEvidence.reason.trim()
        ? sourceEvidence.reason
        : null,
    },
  };
}

/** Normalize legacy stage-level citations into explicitly labeled query context. */
export function normalizeAttackMatches(attackMatches = {}) {
  if (!attackMatches || typeof attackMatches !== 'object' || Array.isArray(attackMatches)) return {};
  return Object.fromEntries(Object.entries(attackMatches).map(([stage, rawResult]) => {
    const result = Array.isArray(rawResult)
      ? { status: 'demo', matches: rawResult }
      : (rawResult && typeof rawResult === 'object' ? rawResult : {});
    const {
      evidence_flow_ids: legacyContextFlows,
      evidence_basis: legacyContextBasis,
      mapping_status: _legacyMappingStatus,
      ...preserved
    } = result;
    const queryContextFlowIds = stringIds(result.query_context_flow_ids ?? legacyContextFlows);
    const queryContextBasis = Array.isArray(result.query_context_basis)
      ? result.query_context_basis.filter(value => typeof value === 'string')
      : (Array.isArray(legacyContextBasis) ? legacyContextBasis.filter(value => typeof value === 'string') : []);
    return [stage, {
      ...preserved,
      retrieval_query_context: {
        flow_ids: queryContextFlowIds,
        basis: queryContextBasis,
        label: 'Stage query context only; not technique-specific evidence.',
      },
      matches: (Array.isArray(result.matches) ? result.matches : []).map(normalizeCandidate),
    }];
  }));
}
