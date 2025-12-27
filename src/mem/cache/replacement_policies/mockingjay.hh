/**
 * Copyright (c) 2024
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer;
 * redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution;
 * neither the name of the copyright holders nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 * Declaration of a Mockingjay ML-based cache replacement policy.
 *
 * This policy uses a lightweight linear model to predict cache line eviction
 * priority based on features like PC hash, age, access count, and reuse distance.
 * It supports both evaluation mode (fixed weights) and training mode (online learning).
 */

#ifndef __MEM_CACHE_REPLACEMENT_POLICIES_MOCKINGJAY_HH__
#define __MEM_CACHE_REPLACEMENT_POLICIES_MOCKINGJAY_HH__

#include <map>
#include <string>
#include <unordered_map>

#include "mem/cache/replacement_policies/base.hh"
#include "params/MockingjayRP.hh"

namespace gem5
{

namespace replacement_policy
{

class Mockingjay : public Base
{
  protected:
    /** Mockingjay-specific implementation of replacement data. */
    struct MockingjayReplData : ReplacementData
    {
        /** Program Counter (PC) associated with this cache line. */
        Addr pc;

        /** Tick on which the entry was inserted. */
        Tick insertTick;

        /** Tick on which the entry was last touched. */
        Tick lastTouchTick;

        /** Number of times this entry has been accessed. */
        uint32_t accessCount;

        /** Reuse distance (number of cache accesses since last use). */
        uint64_t reuseDistance;

        /** Last access counter value (for computing reuse distance). */
        uint64_t lastAccessCounter;

        /** Computed eviction priority (higher = more likely to evict). */
        double priority;

        /**
         * Default constructor. Initialize data.
         */
        MockingjayReplData()
            : pc(0), insertTick(0), lastTouchTick(0),
              accessCount(0), reuseDistance(0), lastAccessCounter(0), priority(0.0) {}
    };

    /** Entry for tracking evicted cache lines (for online learning). */
    struct EvictedEntry
    {
        Addr pc;
        Tick evictTick;
        double features[4];  // pc_hash, age, access_count, reuse_distance
        bool valid;

        EvictedEntry() : pc(0), evictTick(0), valid(false) {}
    };

    /** Model weights for the linear model. */
    double weightPcHash;
    double weightAge;
    double weightAccessCount;
    double weightReuseDistance;
    double bias;

    /** Learning rate for online learning. */
    double learningRate;

    /** Enable/disable online learning. */
    bool enableOnlineLearning;

    /** Path to the weights JSON file. */
    std::string weightsFile;

    /** Eviction tracking table for online learning (64 entries). */
    static const size_t EVICT_TABLE_SIZE = 64;
    // Bug #3 Fix: Mark as mutable to allow modification in const methods
    mutable EvictedEntry evictTable[EVICT_TABLE_SIZE];

    /** Global access counter for tracking reuse distance. */
    // Bug #3 Fix: Mark as mutable to allow modification in const methods
    mutable uint64_t globalAccessCounter;

    /**
     * Load weights from JSON file.
     */
    void loadWeights();

    /**
     * Compute normalized feature value for PC hash.
     * Uses simple modulo hash to normalize PC to [0, 1] range.
     */
    double computePcHashFeature(Addr pc) const;

    /**
     * Compute normalized age feature.
     * Age is time since insertion, normalized by current tick.
     */
    double computeAgeFeature(Tick insertTick, Tick currentTick) const;

    /**
     * Compute normalized access count feature.
     * Uses logarithmic scaling: log(1 + count) / log(1000)
     */
    double computeAccessCountFeature(uint32_t count) const;

    /**
     * Compute normalized reuse distance feature.
     * Uses logarithmic scaling: log(1 + dist) / log(10000)
     */
    double computeReuseDistanceFeature(uint64_t distance) const;

    /**
     * Compute eviction priority using linear model.
     * priority = w1*pc_hash + w2*age + w3*access_count + w4*reuse_dist + bias
     */
    double computePriority(const MockingjayReplData* data) const;

    /**
     * Update model weights based on eviction feedback.
     * Uses simple gradient descent.
     */
    void updateWeights(const EvictedEntry& entry, double target);

    /**
     * Track an evicted entry for online learning.
     */
    void trackEviction(Addr pc, Tick evictTick, const double features[4]) const;

    /**
     * Check if an evicted entry was re-referenced and update weights.
     */
    void checkEvictedReuse(Addr pc, Tick currentTick);

  public:
    typedef MockingjayRPParams Params;
    Mockingjay(const Params &p);
    ~Mockingjay() = default;

    /**
     * Invalidate replacement data to set it as the next probable victim.
     *
     * @param replacement_data Replacement data to be invalidated.
     */
    void invalidate(const std::shared_ptr<ReplacementData>& replacement_data)
                                                                    override;

    /**
     * Touch an entry to update its replacement data.
     * Updates access count and reuse distance.
     *
     * @param replacement_data Replacement data to be touched.
     * @param pkt Packet that generated this access.
     */
    void touch(const std::shared_ptr<ReplacementData>& replacement_data,
               const PacketPtr pkt) override;

    void touch(const std::shared_ptr<ReplacementData>& replacement_data) const
                                                                     override;

    /**
     * Reset replacement data. Used when an entry is inserted.
     * Initializes PC, timestamps, and counters.
     *
     * @param replacement_data Replacement data to be reset.
     * @param pkt Packet that generated this access.
     */
    void reset(const std::shared_ptr<ReplacementData>& replacement_data,
               const PacketPtr pkt) override;

    void reset(const std::shared_ptr<ReplacementData>& replacement_data) const
                                                                     override;

    /**
     * Find replacement victim using ML-based priority.
     * Selects the candidate with highest eviction priority.
     *
     * @param candidates Replacement candidates, selected by indexing policy.
     * @return Replacement entry to be replaced.
     */
    ReplaceableEntry* getVictim(const ReplacementCandidates& candidates) const
                                                                     override;

    /**
     * Instantiate a replacement data entry.
     *
     * @return A shared pointer to the new replacement data.
     */
    std::shared_ptr<ReplacementData> instantiateEntry() override;
};

} // namespace replacement_policy
} // namespace gem5

#endif // __MEM_CACHE_REPLACEMENT_POLICIES_MOCKINGJAY_HH__
