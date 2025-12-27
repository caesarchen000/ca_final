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

    for (size_t i = 0; i + 2 < chronological.size(); ++i) {
        DeltaPair key{chronological[i], chronological[i + 1]};
        auto &entry = patternTable[key];
        entry.counts[chronological[i + 2]]++;
        entry.total++;
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
    if (entry.total >= 20) {
        // Very well-established patterns: reduce threshold by 8%
        adaptive_threshold = std::max(30u, confidenceThreshold - 8);
    } else if (entry.total >= 12) {
        // Well-established patterns: reduce threshold by 5%
        adaptive_threshold = std::max(35u, confidenceThreshold - 5);
    } else if (entry.total >= 6) {
        // Moderately established: reduce threshold by 3%
        adaptive_threshold = std::max(40u, confidenceThreshold - 3);
    }

    // Build candidates with confidence calculation
    std::vector<std::pair<int64_t, unsigned>> candidates;
    for (const auto &count_pair : entry.counts) {
        unsigned confidence = (count_pair.second * 100) / entry.total;
        // Use adaptive threshold
        if (confidence >= adaptive_threshold) {
            candidates.push_back({count_pair.first, confidence});
        }
    }

    // Sort by confidence (highest first)
    std::sort(candidates.begin(), candidates.end(),
              [](const auto &a, const auto &b) { return a.second > b.second; });

    // Return up to 'degree' predictions
    for (size_t i = 0; i < candidates.size() && predicted.size() < degree; i++) {
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

    // Improved fallback: use multiple recent deltas with frequency weighting
    // Count frequency of recent deltas
    std::unordered_map<int64_t, uint32_t> delta_freq;
    size_t lookback = std::min(chronological.size(), static_cast<size_t>(patternLength));
    for (size_t i = chronological.size(); i > chronological.size() - lookback; i--) {
        int64_t delta = chronological[i - 1];
        if (delta != 0) {
            delta_freq[delta]++;
        }
    }

    // Sort by frequency (most common first)
    std::vector<std::pair<int64_t, uint32_t>> freq_sorted(
        delta_freq.begin(), delta_freq.end());
    std::sort(freq_sorted.begin(), freq_sorted.end(),
              [](const auto &a, const auto &b) { return a.second > b.second; });

    // Use most frequent deltas, up to degree
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
