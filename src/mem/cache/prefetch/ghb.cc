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

    // Enhanced stride detection: look for consistent stride patterns
    // This catches simple sequential patterns early and aggressively
    std::vector<int64_t> predicted;
    bool foundMatch = false;
    
    if (chronological.size() >= 2) {
        int64_t last_delta = chronological.back();
        int64_t prev_delta = chronological[chronological.size() - 2];
        
        // Check for consistent stride (2+ consecutive same deltas)
        if (last_delta == prev_delta && last_delta != 0 && 
            std::abs(last_delta) < 200) {
            // Count how many consecutive deltas match (working backwards)
            size_t stride_count = 2;
            for (int i = static_cast<int>(chronological.size()) - 3; 
                 i >= 0; 
                 i--) {
                if (chronological[i] == last_delta) {
                    stride_count++;
                } else {
                    break;
                }
            }
            
            // Strong stride pattern - amplify aggressively
            int64_t stride = last_delta;
            // Use degree, but be more aggressive for longer stride sequences
            // High-confidence strides can prefetch much further ahead
            size_t prefetch_count = degree;
            if (stride_count >= 6) {
                // Very strong pattern - prefetch 2x degree ahead
                prefetch_count = std::min(static_cast<size_t>(degree) * 2, stride_count);
            } else if (stride_count >= 4) {
                // Strong pattern - prefetch 1.5x degree ahead
                prefetch_count = std::min(static_cast<size_t>(degree) + 2, stride_count);
            } else if (stride_count >= 3) {
                // Moderate pattern - slightly more aggressive
                prefetch_count = std::min(static_cast<size_t>(degree) + 1, stride_count);
            }
            for (size_t i = 0; i < prefetch_count; i++) {
                predicted.push_back(stride * static_cast<int64_t>(i + 1));
            }
            foundMatch = true;
        } else if (chronological.size() >= 4) {
            // Check for longer stride patterns (every other, every 3rd, etc.)
            int64_t prev_prev_delta = chronological[chronological.size() - 3];
            int64_t prev_prev_prev_delta = chronological[chronological.size() - 4];
            
            // Check for alternating pattern (A, B, A, B)
            if (last_delta == prev_prev_delta && prev_delta == prev_prev_prev_delta &&
                last_delta != 0 && std::abs(last_delta) < 200) {
                int64_t stride = last_delta;
                for (size_t i = 0; i < degree && i < 3; i++) {
                    predicted.push_back(stride * static_cast<int64_t>(i + 1));
                }
                foundMatch = true;
            }
            
            // Check for strided access with gaps (e.g., +1, +1, +1, +64, +1, +1, +1, +64)
            // This is common in matrix operations
            if (!foundMatch && chronological.size() >= 6) {
                int64_t d1 = chronological[chronological.size() - 1];
                int64_t d2 = chronological[chronological.size() - 2];
                int64_t d3 = chronological[chronological.size() - 3];
                int64_t d4 = chronological[chronological.size() - 4];
                int64_t d5 = chronological[chronological.size() - 5];
                int64_t d6 = chronological[chronological.size() - 6];
                
                // Pattern: small stride, small stride, small stride, large stride, repeat
                if (d1 == d2 && d2 == d3 && d4 == d5 && d5 == d6 && 
                    d1 == d4 && std::abs(d1) < 64 && std::abs(d3) < 200) {
                    // Found strided pattern with gap
                    int64_t stride = d1;
                    for (size_t i = 0; i < degree; i++) {
                        predicted.push_back(stride * static_cast<int64_t>(i + 1));
                    }
                    foundMatch = true;
                }
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
    // Prioritize positive strides (forward sequential access) and smaller absolute values
    std::sort(predicted.begin(), predicted.end(),
              [](int64_t a, int64_t b) {
                  // Prefer positive strides first (forward access)
                  if (a > 0 && b <= 0) return true;
                  if (a <= 0 && b > 0) return false;
                  // Then sort by absolute value (smaller first)
                  return std::abs(a) < std::abs(b);
              });

    // Detect if this is a sequential stride pattern
    bool is_sequential = false;
    int64_t base_stride = 0;
    if (predicted.size() >= 2) {
        // Check if predictions form a sequential pattern (1x, 2x, 3x, ...)
        base_stride = predicted[0];
        if (base_stride != 0 && std::abs(base_stride) < 200) {
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
        if (is_sequential && base_stride != 0) {
            // For sequential patterns, use cumulative addressing with base stride
            // This prefetches further ahead (addr+stride, addr+2*stride, etc.)
            // This is more accurate than using the delta directly
            int64_t cumulative_delta = base_stride * static_cast<int64_t>(i + 1);
            next_addr = static_cast<Addr>(
                static_cast<int64_t>(block_addr) + cumulative_delta);
            current_base = next_addr;
        } else if (is_sequential && i > 0) {
            // Fallback: use cumulative addressing with actual deltas
            next_addr = static_cast<Addr>(
                static_cast<int64_t>(current_base) + delta);
            current_base = next_addr;
        } else {
            // For non-sequential, apply delta to original address
            next_addr = static_cast<Addr>(
                static_cast<int64_t>(block_addr) + delta);
        }

        // Check page boundary - but allow cross-page prefetching intelligently
        if (!samePage(block_addr, next_addr)) {
            // Allow cross-page prefetches if:
            // 1. Small stride (likely same data structure)
            // 2. Sequential pattern (high confidence)
            // 3. Negative stride (backward access, allow for small strides)
            bool allow_cross_page = false;
            
            if (is_sequential && std::abs(base_stride) < 64) {
                // Sequential pattern with small stride - likely same structure
                allow_cross_page = true;
            } else if (std::abs(delta) < 32) {
                // Very small delta - likely same structure
                allow_cross_page = true;
            } else if (delta < 0 && std::abs(delta) < 128) {
                // Small backward stride - allow for stack-like access
                allow_cross_page = true;
            }
            
            if (!allow_cross_page) {
                continue;
            }
        }

        addresses.emplace_back(next_addr, 0);
    }
}

} // namespace prefetch
} // namespace gem5
