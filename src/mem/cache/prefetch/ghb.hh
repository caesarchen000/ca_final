#ifndef __MEM_CACHE_PREFETCH_GHB_HH__
#define __MEM_CACHE_PREFETCH_GHB_HH__

#include "mem/cache/prefetch/ghb_history.hh"
#include "mem/cache/prefetch/queued.hh"

namespace gem5
{

struct GHBPrefetcherParams;

namespace prefetch
{

class GHBPrefetcher : public Queued
{
  protected:
    const unsigned historySize;
    const unsigned patternLength;
    const unsigned degree;
    const bool usePC;
    const unsigned confidenceThreshold;
    GHBHistory historyHelper;

  public:
    GHBPrefetcher(const GHBPrefetcherParams &p);
    void calculatePrefetch(const PrefetchInfo &pfi,
                           std::vector<AddrPriority> &addresses,
                           const CacheAccessor &cache) override;
};

} // namespace prefetch
} // namespace gem5

#endif // __MEM_CACHE_PREFETCH_GHB_HH__
