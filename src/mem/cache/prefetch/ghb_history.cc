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
                
                // Learn 5-delta sequences for very complex patterns
                if (i + 5 < chronological.size()) {
                    DeltaPair chain_key3{chronological[i + 3], chronological[i + 4]};
                    auto &chain_entry3 = patternTable[chain_key3];
                    chain_entry3.counts[chronological[i + 5]]++;
                    chain_entry3.total++;
                }
            }
        }
        
        // Also learn patterns with overlapping windows to capture variations
        // This helps with patterns that have slight variations
        if (i + 3 < chronological.size() && i > 0) {
            // Learn pattern from previous delta to current sequence
            DeltaPair overlap_key{chronological[i - 1], chronological[i]};
            auto &overlap_entry = patternTable[overlap_key];
            overlap_entry.counts[chronological[i + 2]]++;
            overlap_entry.total++;
            
            // Learn even more overlapping patterns for better coverage
            if (i > 1 && i + 4 < chronological.size()) {
                DeltaPair overlap_key2{chronological[i - 2], chronological[i - 1]};
                auto &overlap_entry2 = patternTable[overlap_key2];
                overlap_entry2.counts[chronological[i + 2]]++;
                overlap_entry2.total++;
            }
        }
        
        // Learn reverse patterns (backward sequences) for better coverage
        // This helps with patterns that go backward
        if (i + 2 < chronological.size() && i > 0) {
            int64_t reverse_delta1 = -chronological[i];
            int64_t reverse_delta2 = -chronological[i + 1];
            DeltaPair reverse_key{reverse_delta1, reverse_delta2};
            auto &reverse_entry = patternTable[reverse_key];
            reverse_entry.counts[-chronological[i + 2]]++;
            reverse_entry.total++;
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

    // Multi-pattern matching: try multiple pattern keys to get more predictions
    // This helps with complex access patterns that might match multiple contexts
    std::vector<DeltaPair> pattern_keys;
    
    // Primary pattern: last two deltas
    pattern_keys.push_back({chronological[chronological.size() - 2],
                           chronological.back()});
    
    // Secondary patterns: try longer sequences if available
    if (chronological.size() >= 3) {
        pattern_keys.push_back({chronological[chronological.size() - 3],
                               chronological[chronological.size() - 2]});
    }
    if (chronological.size() >= 4) {
        pattern_keys.push_back({chronological[chronological.size() - 4],
                               chronological[chronological.size() - 3]});
    }

    // Collect candidates from all pattern keys, prioritizing primary pattern
    std::vector<std::pair<int64_t, unsigned>> all_candidates; // delta, weighted_score
    unsigned best_adaptive_threshold = confidenceThreshold;
    const PatternEntry *best_entry = nullptr;
    unsigned best_confidence = 0;
    
    for (size_t key_idx = 0; key_idx < pattern_keys.size(); key_idx++) {
        const auto &key = pattern_keys[key_idx];
        auto it = patternTable.find(key);
        if (it == patternTable.end()) {
            continue;
        }

        const PatternEntry &entry = it->second;
        // Require minimum pattern strength for reliability
        if (entry.total < 2) {
            continue;
        }

        // Adaptive confidence: patterns with more occurrences can use lower threshold
        // Be extremely aggressive to catch more patterns - target 30% improvement
        unsigned adaptive_threshold = confidenceThreshold;
        if (entry.total >= 50) {
            adaptive_threshold = std::max(12u, confidenceThreshold - 30);
        } else if (entry.total >= 40) {
            adaptive_threshold = std::max(15u, confidenceThreshold - 25);
        } else if (entry.total >= 30) {
            adaptive_threshold = std::max(18u, confidenceThreshold - 22);
        } else if (entry.total >= 20) {
            adaptive_threshold = std::max(20u, confidenceThreshold - 18);
        } else if (entry.total >= 12) {
            adaptive_threshold = std::max(22u, confidenceThreshold - 15);
        } else if (entry.total >= 6) {
            adaptive_threshold = std::max(25u, confidenceThreshold - 10);
        } else if (entry.total >= 3) {
            adaptive_threshold = std::max(30u, confidenceThreshold - 8);
        } else if (entry.total >= 2) {
            adaptive_threshold = std::max(35u, confidenceThreshold - 5);
        }
        
        // Track best threshold and entry for later use
        if (adaptive_threshold < best_adaptive_threshold) {
            best_adaptive_threshold = adaptive_threshold;
        }
        
        // Find best confidence in this entry
        unsigned entry_best_conf = 0;
        for (const auto &count_pair : entry.counts) {
            unsigned conf = (count_pair.second * 100) / entry.total;
            if (conf > entry_best_conf) {
                entry_best_conf = conf;
            }
        }
        
        // Track best entry (primary pattern with good confidence)
        if (key_idx == 0 && entry_best_conf >= adaptive_threshold) {
            if (!best_entry || entry_best_conf > best_confidence) {
                best_entry = &entry;
                best_confidence = entry_best_conf;
            }
        }

        // Build candidates with confidence calculation and recency weighting
        // Primary patterns (most recent) get much higher weight
        unsigned pattern_weight = (key_idx == 0) ? 5 : 1; // Increased primary weight
        
        for (const auto &count_pair : entry.counts) {
            unsigned confidence = (count_pair.second * 100) / entry.total;
            if (confidence >= adaptive_threshold) {
                // Weighted score: combine confidence, absolute count, and pattern recency
                unsigned weighted_score = confidence;
                if (count_pair.second >= 5) {
                    weighted_score += 8; // Increased boost
                } else if (count_pair.second >= 3) {
                    weighted_score += 3;
                }
                
        // Apply pattern weight (primary gets 5x multiplier)
        weighted_score *= pattern_weight;
                
                // Check if this delta already exists in candidates
                bool found = false;
                for (auto &existing : all_candidates) {
                    if (existing.first == count_pair.first) {
                        // Merge: take maximum score (prefer primary pattern)
                        existing.second = std::max(existing.second, weighted_score);
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    all_candidates.push_back({count_pair.first, weighted_score});
                }
            }
        }
    }
    
    // If no candidates found, return false
    if (all_candidates.empty()) {
        return false;
    }

    // Sort by weighted score (highest first)
    std::sort(all_candidates.begin(), all_candidates.end(),
              [](const auto &a, const auto &b) { return a.second > b.second; });

    // Determine effective degree based on best entry (primary pattern)
    // Be extremely aggressive for high-confidence patterns - target 30% improvement
    // Start with a higher baseline to be more aggressive overall
    size_t effective_degree = static_cast<size_t>(degree) + 2; // Higher baseline boost
    if (best_entry) {
        if (best_confidence >= 90 && best_entry->total >= 20) {
            // Extremely high confidence - prefetch 10x degree
            effective_degree = std::min(static_cast<size_t>(degree) * 10, 
                                       static_cast<size_t>(degree * 10));
        } else if (best_confidence >= 85 && best_entry->total >= 15) {
            effective_degree = std::min(static_cast<size_t>(degree) * 8, 
                                       static_cast<size_t>(degree * 8));
        } else if (best_confidence >= 80 && best_entry->total >= 10) {
            effective_degree = std::min(static_cast<size_t>(degree) * 6, 
                                       static_cast<size_t>(degree * 6));
        } else if (best_confidence >= 70 && best_entry->total >= 5) {
            effective_degree = std::min(static_cast<size_t>(degree) * 4, 
                                       static_cast<size_t>(degree * 4));
        } else if (best_confidence >= 60 && best_entry->total >= 3) {
            effective_degree = std::min(static_cast<size_t>(degree) * 2, 
                                       static_cast<size_t>(degree * 2));
        } else if (best_confidence >= 50 && best_entry->total >= 2) {
            effective_degree = std::min(static_cast<size_t>(degree) * 2, 
                                       static_cast<size_t>(degree * 2));
        } else if (best_confidence >= 40) {
            effective_degree = std::min(static_cast<size_t>(degree) + 4, 
                                       static_cast<size_t>(degree * 1.8));
        } else if (best_confidence >= 30) {
            effective_degree = std::min(static_cast<size_t>(degree) + 2, 
                                       static_cast<size_t>(degree * 1.5));
        }
        // Even if confidence is lower, we already have baseline boost
    }
    
    // Return up to effective_degree predictions
    // Also include lower-confidence candidates if we don't have enough
    for (size_t i = 0; i < all_candidates.size() && predicted.size() < effective_degree; i++) {
        predicted.push_back(all_candidates[i].first);
    }
    
    // If we still don't have enough predictions, be extremely lenient with thresholds
    // This helps fill the effective_degree for moderate-confidence patterns
    if (predicted.size() < effective_degree && !pattern_keys.empty()) {
        auto it = patternTable.find(pattern_keys[0]);
        if (it != patternTable.end()) {
            const PatternEntry &entry = it->second;
            // Use a lower threshold to get more candidates
            unsigned lenient_threshold = std::max(25u, best_adaptive_threshold - 10);
            for (const auto &count_pair : entry.counts) {
                if (predicted.size() >= effective_degree) break;
                unsigned confidence = (count_pair.second * 100) / entry.total;
                if (confidence >= lenient_threshold) {
                    // Check for duplicates
                    bool is_duplicate = false;
                    for (int64_t existing : predicted) {
                        if (existing == count_pair.first) {
                            is_duplicate = true;
                            break;
                        }
                    }
                    if (!is_duplicate && count_pair.first != 0) {
                        predicted.push_back(count_pair.first);
                    }
                }
            }
        }
        
        // Also try secondary patterns if we still need more
        if (predicted.size() < effective_degree && pattern_keys.size() > 1) {
            for (size_t key_idx = 1; key_idx < pattern_keys.size() && predicted.size() < effective_degree; key_idx++) {
                auto it = patternTable.find(pattern_keys[key_idx]);
                if (it != patternTable.end()) {
                    const PatternEntry &entry = it->second;
                    // Require stronger evidence for secondary patterns
                    if (entry.total < 3) continue;
                    unsigned lenient_threshold = std::max(25u, best_adaptive_threshold - 5);
                    for (const auto &count_pair : entry.counts) {
                        if (predicted.size() >= effective_degree) break;
                        unsigned confidence = (count_pair.second * 100) / entry.total;
                        if (confidence >= lenient_threshold) {
                            // Check for duplicates
                            bool is_duplicate = false;
                            for (int64_t existing : predicted) {
                                if (existing == count_pair.first) {
                                    is_duplicate = true;
                                    break;
                                }
                            }
                            if (!is_duplicate && count_pair.first != 0) {
                                predicted.push_back(count_pair.first);
                            }
                        }
                    }
                }
            }
        }
    }

    // Enhanced prediction chaining: extend predictions to fill degree
    // Chain multiple predictions for better coverage and prefetch distance
    // Be extremely aggressive with chaining to maximize prefetch distance
    size_t max_chain_attempts = effective_degree * 3; // Allow even more chaining attempts
    if (!predicted.empty() && predicted.size() < effective_degree && chronological.size() >= 2) {
        int64_t last_delta = chronological.back();
        
        // Try to chain up to fill the effective degree
        for (size_t chain_attempt = 0; chain_attempt < max_chain_attempts && predicted.size() < effective_degree; chain_attempt++) {
            // Use the most recent prediction (or last delta for first attempt)
            int64_t chain_base = chain_attempt == 0 ? predicted[0] : predicted.back();
            int64_t chain_prev = chain_attempt == 0 ? last_delta : 
                               (predicted.size() > 1 ? predicted[predicted.size() - 2] : last_delta);
            
            // Try to find next pattern in chain
            DeltaPair chain_key{chain_prev, chain_base};
            auto chain_it = patternTable.find(chain_key);
            
            if (chain_it != patternTable.end()) {
                const PatternEntry &chain_entry = chain_it->second;
                // Be extremely lenient for chained predictions to get more coverage
                unsigned min_total = 1u; // Very lenient - only need 1 occurrence
                if (chain_entry.total >= min_total) {
                    // Use much lower threshold for chained predictions to get more coverage
                    unsigned chain_threshold = chain_attempt == 0 ? 
                                             std::max(best_adaptive_threshold, 25u) : 
                                             std::max(best_adaptive_threshold - 10u, 20u);
                    
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
                    
                    // Add chained predictions (up to remaining effective degree)
                    for (const auto &candidate : chain_candidates) {
                        if (predicted.size() >= effective_degree) {
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
    
    // Stride amplification: if we detect a consistent stride, amplify it extremely aggressively
    // This helps with sequential access patterns
    if (predicted.size() < effective_degree && chronological.size() >= 2) {
        int64_t last_delta = chronological.back();
        // Check if last delta matches any prediction (indicating stride)
        for (int64_t pred : predicted) {
            // More lenient stride matching - allow small differences
            if ((pred == last_delta || std::abs(pred - last_delta) <= 2) && 
                std::abs(pred) > 0 && std::abs(pred) < 300) {
                // Found a stride pattern, amplify it extremely aggressively
                int64_t stride = pred;
                size_t amplify_count = effective_degree - predicted.size();
                // Amplify up to 3x more for strong strides
                if (std::abs(stride) < 128) {
                    amplify_count = std::min(amplify_count * 3, effective_degree - predicted.size());
                } else if (std::abs(stride) < 256) {
                    amplify_count = std::min(amplify_count * 2, effective_degree - predicted.size());
                }
                for (size_t i = predicted.size(); i < predicted.size() + amplify_count && i < effective_degree; i++) {
                    int64_t amplified = stride * static_cast<int64_t>(i + 1);
                    // Check for duplicates
                    bool is_duplicate = false;
                    for (int64_t existing : predicted) {
                        if (existing == amplified || std::abs(existing - amplified) <= 2) {
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
        
        // Also check if chronological history shows a consistent stride
        if (predicted.size() < effective_degree && chronological.size() >= 3) {
            int64_t stride_candidate = chronological.back();
            if (stride_candidate != 0 && std::abs(stride_candidate) < 300) {
                // Check if this stride appears multiple times
                size_t stride_count = 1;
                for (int i = static_cast<int>(chronological.size()) - 2; 
                     i >= 0 && i >= static_cast<int>(chronological.size()) - 6; i--) {
                    if (chronological[i] == stride_candidate || 
                        std::abs(chronological[i] - stride_candidate) <= 2) {
                        stride_count++;
                    } else {
                        break;
                    }
                }
                if (stride_count >= 2) {
                    // Strong stride in history - amplify it
                    size_t amplify_count = effective_degree - predicted.size();
                    for (size_t i = 0; i < amplify_count && predicted.size() < effective_degree; i++) {
                        int64_t amplified = stride_candidate * static_cast<int64_t>(i + 1);
                        // Check for duplicates
                        bool is_duplicate = false;
                        for (int64_t existing : predicted) {
                            if (existing == amplified || std::abs(existing - amplified) <= 2) {
                                is_duplicate = true;
                                break;
                            }
                        }
                        if (!is_duplicate) {
                            predicted.push_back(amplified);
                        }
                    }
                }
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

    // Sort by weighted score (frequency + recency bonus) - more aggressive weighting
    std::vector<std::pair<int64_t, uint32_t>> freq_sorted(
        delta_freq.begin(), delta_freq.end());
    std::sort(freq_sorted.begin(), freq_sorted.end(),
              [&delta_recency](const auto &a, const auto &b) {
                  // Weight: frequency * 3 + recency * 2 (prioritize frequent and recent)
                  uint32_t recency_a = delta_recency.count(a.first) ? delta_recency.at(a.first) : 0;
                  uint32_t recency_b = delta_recency.count(b.first) ? delta_recency.at(b.first) : 0;
                  uint32_t score_a = a.second * 3 + recency_a * 2;
                  uint32_t score_b = b.second * 3 + recency_b * 2;
                  if (score_a != score_b) {
                      return score_a > score_b;
                  }
                  // Tie-breaker: prefer positive strides (forward access)
                  if (a.first > 0 && b.first <= 0) return true;
                  if (a.first <= 0 && b.first > 0) return false;
                  // Secondary tie-breaker: prefer smaller absolute deltas
                  return std::abs(a.first) < std::abs(b.first);
              });

    // Check if the most frequent delta forms a stride pattern
    // If so, amplify it very aggressively
    if (!freq_sorted.empty() && freq_sorted[0].second >= 1) {
        int64_t candidate_stride = freq_sorted[0].first;
        // Check if this delta appears consecutively in recent history
        size_t consecutive_count = 0;
        for (size_t i = chronological.size(); i > 0 && i > chronological.size() - 8; i--) {
            if (chronological[i - 1] == candidate_stride) {
                consecutive_count++;
            } else {
                break;
            }
        }
        
        if (consecutive_count >= 1 && std::abs(candidate_stride) < 300) {
            // Found a stride pattern - amplify it extremely aggressively
            size_t prefetch_count = static_cast<size_t>(degree) + 2; // Baseline boost
            if (consecutive_count >= 8) {
                prefetch_count = std::min(static_cast<size_t>(degree) * 6, 
                                         static_cast<size_t>(degree * 6));
            } else if (consecutive_count >= 6) {
                prefetch_count = std::min(static_cast<size_t>(degree) * 5, 
                                         static_cast<size_t>(degree * 5));
            } else if (consecutive_count >= 4) {
                prefetch_count = std::min(static_cast<size_t>(degree) * 4, 
                                         static_cast<size_t>(degree * 4));
            } else if (consecutive_count >= 2) {
                prefetch_count = std::min(static_cast<size_t>(degree) * 2, 
                                         static_cast<size_t>(degree * 2));
            } else {
                prefetch_count = std::min(static_cast<size_t>(degree) + 2, 
                                         static_cast<size_t>(degree * 1.5));
            }
            for (size_t i = 0; i < prefetch_count; i++) {
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
