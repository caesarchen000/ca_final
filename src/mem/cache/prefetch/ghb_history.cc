/*
 * Implementation of the lightweight GHB history helper.
 */

#include "mem/cache/prefetch/ghb_history.hh"

#include <algorithm>

#include "base/logging.hh"

namespace gem5
{

namespace prefetch
{

GHBHistory::GHBHistory(unsigned history_size, unsigned pattern_length,
                       unsigned degree_, bool use_pc, unsigned page_bytes,
                       unsigned confidence_threshold)
    : historySize(std::max(1u, history_size)),
      patternLength(std::max(1u, pattern_length)),
      degree(std::max(1u, degree_)),
      usePC(use_pc),
      pageBytes(std::max(1u, page_bytes)),
      confidenceThreshold(std::min(100u, confidence_threshold)),
      history(historySize),
      head(0),
      filled(false),
      sequenceCounter(1)
{
}

void
GHBHistory::reset()
{
    for (auto &entry : history) {
        entry.addr = 0;
        entry.seq = 0;
        for (auto &link : entry.links) {
            link = LinkInfo{};
        }
    }
    for (auto &map : lastIndex) {
        map.clear();
    }
    head = 0;
    filled = false;
    sequenceCounter = 1;
    patternTable.clear();
}

void
GHBHistory::evictIndex(int32_t slot)
{
    removeIndexMappings(slot);
}

void
GHBHistory::removeIndexMappings(int32_t slot)
{
    GHBEntry &victim = history[slot];
    for (size_t i = 0; i < NumCorrelationKeys; ++i) {
        if (!victim.links[i].keyValid) {
            continue;
        }
        auto &indexMap = lastIndex[i];
        auto it = indexMap.find(victim.links[i].keyValue);
        if (it != indexMap.end() && it->second == slot) {
            indexMap.erase(it);
        }
        victim.links[i].keyValid = false;
    }
}

void
GHBHistory::assignCorrelation(GHBEntry &entry, int32_t slot,
                              CorrelationKey key, uint64_t value)
{
    const size_t idx = static_cast<size_t>(key);
    auto &link = entry.links[idx];
    link.prev = -1;
    link.prevSeq = 0;
    link.keyValid = true;
    link.keyValue = value;

    auto &indexMap = lastIndex[idx];
    auto it = indexMap.find(value);
    if (it != indexMap.end()) {
        link.prev = it->second;
        link.prevSeq = history[it->second].seq;
    }
    indexMap[value] = slot;
}

int32_t
GHBHistory::insert(const AccessInfo &access)
{
    if (historySize == 0) {
        return -1;
    }

    if (filled) {
        evictIndex(head);
    }

    const int32_t slot = head;
    GHBEntry &entry = history[slot];
    entry.addr = access.addr;
    entry.seq = sequenceCounter++;

    if (usePC && access.pc.has_value()) {
        assignCorrelation(entry, slot, CorrelationKey::PC,
                          access.pc.value());
    } else {
        entry.links[static_cast<size_t>(CorrelationKey::PC)] = LinkInfo{};
    }

    assignCorrelation(entry, slot, CorrelationKey::Page,
                      computePage(access.addr));

    head = (head + 1) % historySize;
    if (head == 0) {
        filled = true;
    }
    return slot;
}

bool
GHBHistory::buildPattern(int32_t index, CorrelationKey key,
                         std::vector<int64_t> &deltas) const
{
    deltas.clear();
    const size_t linkIdx = static_cast<size_t>(key);
    if (index < 0 || static_cast<size_t>(index) >= history.size()) {
        return false;
    }

    int32_t current = index;
    while (deltas.size() < patternLength) {
        const GHBEntry &entry = history[current];
        const LinkInfo &link = entry.links[linkIdx];
        if (link.prev < 0) {
            break;
        }
        const GHBEntry &prev_entry = history[link.prev];
        if (prev_entry.seq != link.prevSeq) {
            break;
        }

        deltas.push_back(static_cast<int64_t>(entry.addr) -
                         static_cast<int64_t>(prev_entry.addr));
        current = link.prev;
    }
    return !deltas.empty();
}

void
GHBHistory::updatePatternTable(const std::vector<int64_t> &chronological)
{
    if (chronological.size() < 3) {
        return;
    }

    // Update pattern table with all possible delta pairs
    // This helps learn patterns faster
    for (size_t i = 0; i + 2 < chronological.size(); ++i) {
        DeltaPair key{chronological[i], chronological[i + 1]};
        auto &entry = patternTable[key];
        int64_t next_delta = chronological[i + 2];
        entry.counts[next_delta]++;
        entry.total++;
        
        // Also learn longer patterns (3-delta, 4-delta sequences) for better prediction
        // This helps with complex access patterns
        if (i + 3 < chronological.size()) {
            // Learn the pattern: (delta[i], delta[i+1]) -> delta[i+2] -> delta[i+3]
            // This creates a chain of predictions
            DeltaPair chain_key{chronological[i + 1], chronological[i + 2]};
            auto &chain_entry = patternTable[chain_key];
            chain_entry.counts[chronological[i + 3]]++;
            chain_entry.total++;
            
            // Learn 4-delta sequences for even more complex patterns
            if (i + 4 < chronological.size()) {
                DeltaPair chain_key2{chronological[i + 2], chronological[i + 3]};
                auto &chain_entry2 = patternTable[chain_key2];
                chain_entry2.counts[chronological[i + 4]]++;
                chain_entry2.total++;
            }
        }
    }
}

bool
GHBHistory::findPatternMatch(const std::vector<int64_t> &chronological,
                             std::vector<int64_t> &predicted) const
{
    predicted.clear();
    if (chronological.size() < 2) {
        return false;
    }

    DeltaPair key{chronological[chronological.size() - 2],
                  chronological.back()};
    auto it = patternTable.find(key);
    if (it == patternTable.end()) {
        return false;
    }

    const PatternEntry &entry = it->second;
    // Require minimum pattern strength for reliability
    if (entry.total < 2) {
        return false;
    }

    // Adaptive confidence: patterns with more occurrences can use lower threshold
    // This allows us to be more aggressive with well-established patterns
    unsigned adaptive_threshold = confidenceThreshold;
    if (entry.total >= 30) {
        // Extremely well-established patterns: reduce threshold by 12%
        adaptive_threshold = std::max(25u, confidenceThreshold - 12);
    } else if (entry.total >= 20) {
        // Very well-established patterns: reduce threshold by 10%
        adaptive_threshold = std::max(28u, confidenceThreshold - 10);
    } else if (entry.total >= 12) {
        // Well-established patterns: reduce threshold by 6%
        adaptive_threshold = std::max(32u, confidenceThreshold - 6);
    } else if (entry.total >= 6) {
        // Moderately established: reduce threshold by 4%
        adaptive_threshold = std::max(38u, confidenceThreshold - 4);
    }

    // Build candidates with confidence calculation
    // Weight by both confidence percentage and absolute count for better prioritization
    std::vector<std::pair<int64_t, unsigned>> candidates;
    for (const auto &count_pair : entry.counts) {
        unsigned confidence = (count_pair.second * 100) / entry.total;
        // Use adaptive threshold
        if (confidence >= adaptive_threshold) {
            // Weighted score: combine confidence and absolute count
            // This helps prioritize patterns with both high confidence and high frequency
            unsigned weighted_score = confidence;
            if (count_pair.second >= 5) {
                // Boost for patterns seen many times
                weighted_score += 5;
            } else if (count_pair.second >= 3) {
                weighted_score += 2;
            }
            candidates.push_back({count_pair.first, weighted_score});
        }
    }

    // Sort by weighted score (highest first)
    std::sort(candidates.begin(), candidates.end(),
              [](const auto &a, const auto &b) { return a.second > b.second; });

    // Return up to 'degree' predictions, but use adaptive degree for high-confidence patterns
    // High-confidence patterns can use more aggressive prefetching
    size_t effective_degree = degree;
    if (!candidates.empty() && candidates[0].second >= 85 && entry.total >= 15) {
        // Extremely high confidence with very strong pattern - be very aggressive
        effective_degree = std::min(static_cast<size_t>(degree) + 3, 
                                   static_cast<size_t>(degree * 1.8));
    } else if (!candidates.empty() && candidates[0].second >= 80 && entry.total >= 10) {
        // Very high confidence with strong pattern - be more aggressive
        effective_degree = std::min(static_cast<size_t>(degree) + 2, 
                                   static_cast<size_t>(degree * 1.5));
    } else if (!candidates.empty() && candidates[0].second >= 70 && entry.total >= 5) {
        // High confidence - slightly more aggressive
        effective_degree = static_cast<size_t>(degree) + 1;
    }
    
    for (size_t i = 0; i < candidates.size() && predicted.size() < effective_degree; i++) {
        predicted.push_back(candidates[i].first);
    }

    // Enhanced prediction chaining: extend predictions to fill degree
    // Chain multiple predictions for better coverage and prefetch distance
    if (!predicted.empty() && predicted.size() < degree && chronological.size() >= 2) {
        int64_t last_delta = chronological.back();
        
        // Try to chain up to fill the degree
        for (size_t chain_attempt = 0; chain_attempt < degree && predicted.size() < degree; chain_attempt++) {
            // Use the most recent prediction (or last delta for first attempt)
            int64_t chain_base = chain_attempt == 0 ? predicted[0] : predicted.back();
            int64_t chain_prev = chain_attempt == 0 ? last_delta : 
                               (predicted.size() > 1 ? predicted[predicted.size() - 2] : last_delta);
            
            // Try to find next pattern in chain
            DeltaPair chain_key{chain_prev, chain_base};
            auto chain_it = patternTable.find(chain_key);
            
            if (chain_it != patternTable.end()) {
                const PatternEntry &chain_entry = chain_it->second;
                // Require stronger evidence for chained predictions (but less strict for later chains)
                unsigned min_total = chain_attempt == 0 ? 3u : 2u;
                if (chain_entry.total >= min_total) {
                    // Use slightly lower threshold for chained predictions to get more coverage
                    unsigned chain_threshold = chain_attempt == 0 ? 
                                             std::max(adaptive_threshold + 5u, 45u) : 
                                             std::max(adaptive_threshold, 40u);
                    
                    // Find best candidates from chained pattern
                    std::vector<std::pair<int64_t, unsigned>> chain_candidates;
                    for (const auto &count_pair : chain_entry.counts) {
                        unsigned chain_conf = (count_pair.second * 100) / chain_entry.total;
                        if (chain_conf >= chain_threshold) {
                            chain_candidates.push_back({count_pair.first, chain_conf});
                        }
                    }
                    
                    // Sort by confidence
                    std::sort(chain_candidates.begin(), chain_candidates.end(),
                              [](const auto &a, const auto &b) { return a.second > b.second; });
                    
                    // Add chained predictions (up to remaining degree)
                    for (const auto &candidate : chain_candidates) {
                        if (predicted.size() >= degree) {
                            break;
                        }
                        // Check for duplicates
                        bool is_duplicate = false;
                        for (int64_t existing : predicted) {
                            if (existing == candidate.first) {
                                is_duplicate = true;
                                break;
                            }
                        }
                        if (!is_duplicate && candidate.first != 0) {
                            predicted.push_back(candidate.first);
                            break; // Add one per chain attempt
                        }
                    }
                } else {
                    // No strong chain pattern, stop chaining
                    break;
                }
            } else {
                // No chain pattern found, stop chaining
                break;
            }
        }
    }
    
    // Stride amplification: if we detect a consistent stride, amplify it
    // This helps with sequential access patterns
    if (predicted.size() < degree && chronological.size() >= 2) {
        int64_t last_delta = chronological.back();
        // Check if last delta matches any prediction (indicating stride)
        for (int64_t pred : predicted) {
            if (pred == last_delta && std::abs(pred) > 0 && std::abs(pred) < 100) {
                // Found a stride pattern, amplify it
                int64_t stride = pred;
                for (size_t i = predicted.size(); i < degree; i++) {
                    int64_t amplified = stride * static_cast<int64_t>(i + 1);
                    // Check for duplicates
                    bool is_duplicate = false;
                    for (int64_t existing : predicted) {
                        if (existing == amplified) {
                            is_duplicate = true;
                            break;
                        }
                    }
                    if (!is_duplicate) {
                        predicted.push_back(amplified);
                    } else {
                        break;
                    }
                }
                break;
            }
        }
    }

    return !predicted.empty();
}

void
GHBHistory::fallbackPattern(const std::vector<int64_t> &chronological,
                            std::vector<int64_t> &predicted) const
{
    predicted.clear();
    if (chronological.empty()) {
        return;
    }

    // Improved fallback: use multiple recent deltas with frequency and recency weighting
    // Count frequency of recent deltas, with recency bonus
    std::unordered_map<int64_t, uint32_t> delta_freq;
    std::unordered_map<int64_t, uint32_t> delta_recency; // Track how recent each delta is
    size_t lookback = std::min(chronological.size(), static_cast<size_t>(patternLength));
    for (size_t i = chronological.size(); i > chronological.size() - lookback; i--) {
        int64_t delta = chronological[i - 1];
        if (delta != 0) {
            delta_freq[delta]++;
            // More recent deltas get higher recency score
            delta_recency[delta] = std::max(delta_recency[delta], 
                                           static_cast<uint32_t>(chronological.size() - i + 1));
        }
    }

    // Sort by weighted score (frequency + recency bonus)
    std::vector<std::pair<int64_t, uint32_t>> freq_sorted(
        delta_freq.begin(), delta_freq.end());
    std::sort(freq_sorted.begin(), freq_sorted.end(),
              [&delta_recency](const auto &a, const auto &b) {
                  // Weight: frequency * 2 + recency (prioritize frequent and recent)
                  uint32_t recency_a = delta_recency.count(a.first) ? delta_recency.at(a.first) : 0;
                  uint32_t recency_b = delta_recency.count(b.first) ? delta_recency.at(b.first) : 0;
                  uint32_t score_a = a.second * 2 + recency_a;
                  uint32_t score_b = b.second * 2 + recency_b;
                  if (score_a != score_b) {
                      return score_a > score_b;
                  }
                  // Tie-breaker: prefer positive strides (forward access)
                  if (a.first > 0 && b.first <= 0) return true;
                  if (a.first <= 0 && b.first > 0) return false;
                  return std::abs(a.first) < std::abs(b.first);
              });

    // Check if the most frequent delta forms a stride pattern
    // If so, amplify it aggressively
    if (!freq_sorted.empty() && freq_sorted[0].second >= 2) {
        int64_t candidate_stride = freq_sorted[0].first;
        // Check if this delta appears consecutively in recent history
        size_t consecutive_count = 0;
        for (size_t i = chronological.size(); i > 0 && i > chronological.size() - 5; i--) {
            if (chronological[i - 1] == candidate_stride) {
                consecutive_count++;
            } else {
                break;
            }
        }
        
        if (consecutive_count >= 2 && std::abs(candidate_stride) < 200) {
            // Found a stride pattern - amplify it
            for (size_t i = 0; i < degree; i++) {
                predicted.push_back(candidate_stride * static_cast<int64_t>(i + 1));
            }
            return; // Early return since we found a good stride
        }
    }
    
    // Use most frequent/recent deltas, up to degree
    for (size_t i = 0; i < freq_sorted.size() && predicted.size() < degree; i++) {
        predicted.push_back(freq_sorted[i].first);
    }

    // If we still don't have enough, fill with recent deltas in order
    if (predicted.size() < degree) {
        for (size_t i = chronological.size(); i > 0 && predicted.size() < degree; i--) {
            int64_t delta = chronological[i - 1];
            if (delta != 0) {
                // Avoid duplicates
                bool is_duplicate = false;
                for (int64_t existing : predicted) {
                    if (existing == delta) {
                        is_duplicate = true;
                        break;
                    }
                }
                if (!is_duplicate) {
                    predicted.push_back(delta);
                }
            }
        }
    }
}

} // namespace prefetch
} // namespace gem5
