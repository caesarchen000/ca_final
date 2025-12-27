/*
 * Lightweight helper for GHB history/pattern tracking so it can be unit tested
 * without instantiating the full gem5 prefetcher stack.
 */

#ifndef __MEM_CACHE_PREFETCH_GHB_HISTORY_HH__
#define __MEM_CACHE_PREFETCH_GHB_HISTORY_HH__

#include <array>
#include <optional>
#include <unordered_map>
#include <vector>

#include "base/types.hh"

namespace gem5
{

namespace prefetch
{

class GHBHistory
{
  public:
    enum class CorrelationKey : uint8_t
    {
        PC = 0,
        Page = 1
    };
    static constexpr size_t NumCorrelationKeys = 2;

    struct AccessInfo
    {
        Addr addr = 0;
        std::optional<Addr> pc;
    };

    GHBHistory(unsigned history_size, unsigned pattern_length, unsigned degree,
               bool use_pc, unsigned page_bytes,
               unsigned confidence_threshold);

    bool empty() const { return historySize == 0; }
    void reset();

    int32_t insert(const AccessInfo &access);
    bool buildPattern(int32_t index, CorrelationKey key,
                      std::vector<int64_t> &deltas) const;
    void updatePatternTable(const std::vector<int64_t> &chronological);
    bool findPatternMatch(const std::vector<int64_t> &chronological,
                          std::vector<int64_t> &predicted) const;
    void fallbackPattern(const std::vector<int64_t> &chronological,
                         std::vector<int64_t> &predicted) const;

  private:
    struct LinkInfo
    {
        int32_t prev = -1;
        uint64_t prevSeq = 0;
        uint64_t keyValue = 0;
        bool keyValid = false;
    };

    struct GHBEntry
    {
        Addr addr = 0;
        std::array<LinkInfo, NumCorrelationKeys> links;
        uint64_t seq = 0;
    };

    struct DeltaPair
    {
        int64_t first = 0;
        int64_t second = 0;

        bool operator==(const DeltaPair &rhs) const
        {
            return first == rhs.first && second == rhs.second;
        }
    };

    struct DeltaPairHash
    {
        std::size_t operator()(const DeltaPair &p) const
        {
            return std::hash<int64_t>{}(p.first) ^
                   (std::hash<int64_t>{}(p.second) << 1);
        }
    };

    struct PatternEntry
    {
        std::unordered_map<int64_t, uint32_t> counts;
        uint32_t total = 0;
    };

    unsigned historySize;
    unsigned patternLength;
    unsigned degree;
    bool usePC;
    unsigned pageBytes;
    unsigned confidenceThreshold;

    std::vector<GHBEntry> history;
    std::array<std::unordered_map<uint64_t, int32_t>, NumCorrelationKeys>
        lastIndex;
    int32_t head;
    bool filled;
    uint64_t sequenceCounter;
    std::unordered_map<DeltaPair, PatternEntry, DeltaPairHash> patternTable;

    void evictIndex(int32_t slot);
    void removeIndexMappings(int32_t slot);
    void assignCorrelation(GHBEntry &entry, int32_t slot,
                           CorrelationKey key, uint64_t value);
    uint64_t computePage(Addr addr) const { return addr / pageBytes; }
};

} // namespace prefetch
} // namespace gem5

#endif // __MEM_CACHE_PREFETCH_GHB_HISTORY_HH__
