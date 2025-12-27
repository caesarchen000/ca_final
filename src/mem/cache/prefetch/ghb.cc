#include "mem/cache/prefetch/ghb.hh"

#include <algorithm>

#include "base/logging.hh"
#include "params/GHBPrefetcher.hh"

namespace gem5
{

namespace prefetch
{

GHBPrefetcher::GHBPrefetcher(const GHBPrefetcherParams &p)
    : Queued(p),
      historySize(std::max(1u, p.history_size)),
      patternLength(std::max(1u, p.pattern_length)),
      degree(std::max(1u, p.degree)),
      usePC(p.use_pc),
      confidenceThreshold(
          std::min(100u,
                   std::max(0u, static_cast<unsigned>(p.confidence_threshold)))),
      historyHelper(historySize, patternLength, degree, usePC,
                    static_cast<unsigned>(pageBytes),
                    confidenceThreshold)
{
}

void
GHBPrefetcher::calculatePrefetch(
    const PrefetchInfo &pfi, std::vector<AddrPriority> &addresses,
    const CacheAccessor &cache)
{
    (void)cache;
    if (historyHelper.empty()) {
        return;
    }

    Addr block_addr = blockAddress(pfi.getAddr());

    GHBHistory::AccessInfo access{block_addr};
    if (usePC && pfi.hasPC()) {
        access.pc = pfi.getPC();
    }

    int32_t idx = historyHelper.insert(access);
    if (idx < 0) {
        return;
    }

    // Try PC-based pattern first (more specific)
    std::vector<int64_t> pc_deltas;
    pc_deltas.reserve(patternLength);
    bool hasPCPattern =
        historyHelper.buildPattern(idx, GHBHistory::CorrelationKey::PC, pc_deltas);
    
    // Try Page-based pattern as fallback or supplement
    std::vector<int64_t> page_deltas;
    page_deltas.reserve(patternLength);
    bool hasPagePattern =
        historyHelper.buildPattern(idx, GHBHistory::CorrelationKey::Page, page_deltas);

    // Prefer PC pattern if available (more specific), otherwise use Page pattern
    std::vector<int64_t> deltas;
    bool hasPattern = false;
    if (hasPCPattern) {
        deltas = pc_deltas;
        hasPattern = true;
    } else if (hasPagePattern) {
        deltas = page_deltas;
        hasPattern = true;
    }

    if (!hasPattern) {
        return;
    }

    std::vector<int64_t> chronological(deltas.rbegin(), deltas.rend());
    historyHelper.updatePatternTable(chronological);

    // Quick stride detection: if recent deltas are consistent, use stride prefetching
    // This catches simple sequential patterns early
    std::vector<int64_t> predicted;
    bool foundMatch = false;
    
    if (chronological.size() >= 3) {
        // Check if last 2-3 deltas are the same (strong stride indicator)
        int64_t last_delta = chronological.back();
        int64_t prev_delta = chronological[chronological.size() - 2];
        
        if (last_delta == prev_delta && last_delta != 0 && 
            std::abs(last_delta) < 100) {
            // Strong stride pattern detected - amplify it
            int64_t stride = last_delta;
            for (size_t i = 0; i < degree; i++) {
                predicted.push_back(stride * static_cast<int64_t>(i + 1));
            }
            foundMatch = true;
        } else if (chronological.size() >= 3) {
            // Check if last 3 deltas show a pattern
            int64_t prev_prev_delta = chronological[chronological.size() - 3];
            if (last_delta == prev_prev_delta && last_delta != 0 && 
                std::abs(last_delta) < 100) {
                // Alternating or repeating pattern
                int64_t stride = last_delta;
                for (size_t i = 0; i < degree && i < 2; i++) {
                    predicted.push_back(stride * static_cast<int64_t>(i + 1));
                }
                foundMatch = true;
            }
        }
    }
    
    // Try pattern matching with primary pattern if stride detection didn't work
    if (!foundMatch) {
        foundMatch = historyHelper.findPatternMatch(chronological, predicted);
    }
    
    // If PC pattern didn't match well and we have Page pattern, try it
    // Only update pattern table with page pattern if we're actually using it
    // This reduces pattern table pollution
    if (!foundMatch && hasPagePattern && !page_deltas.empty() && 
        (!hasPCPattern || page_deltas != pc_deltas)) {
        std::vector<int64_t> page_chronological(page_deltas.rbegin(), page_deltas.rend());
        // Update pattern table with page pattern only when we use it
        historyHelper.updatePatternTable(page_chronological);
        historyHelper.findPatternMatch(page_chronological, predicted);
    }
    
    // Fallback if still no predictions
    if (predicted.empty()) {
        historyHelper.fallbackPattern(chronological, predicted);
    }
    
    if (predicted.empty()) {
        return;
    }

    // Generate prefetch addresses with better ordering
    // Sort predictions by absolute delta value (prefer smaller strides first)
    // This helps with sequential access patterns
    std::sort(predicted.begin(), predicted.end(),
              [](int64_t a, int64_t b) {
                  return std::abs(a) < std::abs(b);
              });

    // Detect if this is a sequential stride pattern
    bool is_sequential = false;
    if (predicted.size() >= 2) {
        // Check if predictions form a sequential pattern (1x, 2x, 3x, ...)
        int64_t base_stride = predicted[0];
        if (base_stride != 0 && std::abs(base_stride) < 100) {
            bool sequential = true;
            for (size_t i = 1; i < predicted.size() && i < 3; i++) {
                int64_t expected = base_stride * static_cast<int64_t>(i + 1);
                if (predicted[i] != expected) {
                    sequential = false;
                    break;
                }
            }
            is_sequential = sequential;
        }
    }

    // Generate prefetches from the base address
    // For sequential patterns, use cumulative addresses for better distance
    // For other patterns, each delta is applied to the original block_addr
    Addr current_base = block_addr;
    for (size_t i = 0; i < predicted.size(); i++) {
        int64_t delta = predicted[i];
        if (delta == 0) {
            continue;
        }

        Addr next_addr;
        if (is_sequential && i > 0) {
            // For sequential patterns, use cumulative addressing
            // This prefetches further ahead (addr+stride, addr+2*stride, etc.)
            next_addr = static_cast<Addr>(
                static_cast<int64_t>(current_base) + delta);
            current_base = next_addr;
        } else {
            // For non-sequential, apply delta to original address
            next_addr = static_cast<Addr>(
                static_cast<int64_t>(block_addr) + delta);
        }

        // Check page boundary - but allow some cross-page prefetching
        // for very small deltas (likely same logical structure)
        if (!samePage(block_addr, next_addr)) {
            // Only skip if delta is large (likely different structure)
            if (std::abs(delta) > static_cast<int64_t>(pageBytes / 2)) {
                continue;
            }
        }

        addresses.emplace_back(next_addr, 0);
    }
}

} // namespace prefetch
} // namespace gem5
