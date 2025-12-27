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

#include "mem/cache/replacement_policies/mockingjay.hh"

#include <algorithm>
#include <cassert>
#include <cmath>
#include <fstream>
#include <limits>
#include <memory>

#include "base/logging.hh"
#include "base/trace.hh"
#include "debug/CacheRepl.hh"
#include "params/MockingjayRP.hh"
#include "sim/cur_tick.hh"

// Simple JSON parsing for weights file
// We'll use a very basic parser to avoid external dependencies
namespace
{

// Simple helper to trim whitespace
std::string trim(const std::string& str)
{
    size_t first = str.find_first_not_of(" \t\n\r");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\n\r");
    return str.substr(first, (last - first + 1));
}

// Parse a simple JSON number value
double parseJsonNumber(const std::string& json, const std::string& key)
{
    size_t pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return 0.0;

    pos = json.find(":", pos);
    if (pos == std::string::npos) return 0.0;

    pos++;
    size_t end = json.find_first_of(",}", pos);
    if (end == std::string::npos) return 0.0;

    std::string value = trim(json.substr(pos, end - pos));
    return std::stod(value);
}

// Parse a simple JSON boolean value
bool parseJsonBool(const std::string& json, const std::string& key)
{
    size_t pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return false;

    pos = json.find(":", pos);
    if (pos == std::string::npos) return false;

    pos++;
    size_t end = json.find_first_of(",}", pos);
    if (end == std::string::npos) return false;

    std::string value = trim(json.substr(pos, end - pos));
    return (value == "true");
}

// Extract weight value from feature object
double extractWeight(const std::string& json, const std::string& featureName)
{
    size_t pos = 0;
    while ((pos = json.find("\"name\"", pos)) != std::string::npos) {
        size_t nameStart = json.find(":", pos);
        if (nameStart == std::string::npos) break;

        size_t nameValueStart = json.find("\"", nameStart + 1);
        size_t nameValueEnd = json.find("\"", nameValueStart + 1);

        if (nameValueStart == std::string::npos || nameValueEnd == std::string::npos)
            break;

        std::string name = json.substr(nameValueStart + 1,
                                       nameValueEnd - nameValueStart - 1);

        if (name == featureName) {
            // Found the right feature, now extract weight
            size_t weightPos = json.find("\"weight\"", nameValueEnd);
            if (weightPos == std::string::npos) break;

            size_t colonPos = json.find(":", weightPos);
            size_t endPos = json.find_first_of(",}", colonPos);

            if (colonPos != std::string::npos && endPos != std::string::npos) {
                std::string weightStr = trim(json.substr(colonPos + 1,
                                                         endPos - colonPos - 1));
                return std::stod(weightStr);
            }
        }

        pos = nameValueEnd;
    }

    return 0.0;
}

} // anonymous namespace

namespace gem5
{

namespace replacement_policy
{

Mockingjay::Mockingjay(const Params &p)
    : Base(p),
      weightPcHash(0.25),
      weightAge(0.35),
      weightAccessCount(-0.30),
      weightReuseDistance(0.40),
      bias(0.0),
      learningRate(p.learning_rate),
      enableOnlineLearning(p.enable_online_learning),
      weightsFile(p.weights_file),
      globalAccessCounter(0)
{
    // Initialize eviction table
    for (size_t i = 0; i < EVICT_TABLE_SIZE; i++) {
        evictTable[i].valid = false;
    }

    // Load weights from file if specified
    if (!weightsFile.empty()) {
        loadWeights();
    }

    DPRINTF(CacheRepl, "Mockingjay: Initialized with weights - "
            "pc_hash: %f, age: %f, access_count: %f, reuse_dist: %f, bias: %f\n",
            weightPcHash, weightAge, weightAccessCount, weightReuseDistance, bias);
    DPRINTF(CacheRepl, "Mockingjay: Learning rate: %f, Online learning: %s\n",
            learningRate, enableOnlineLearning ? "enabled" : "disabled");
}

void
Mockingjay::loadWeights()
{
    std::ifstream file(weightsFile);
    if (!file.is_open()) {
        warn("Mockingjay: Could not open weights file '%s', using defaults\n",
             weightsFile);
        return;
    }

    // Read entire file into string
    std::string json((std::istreambuf_iterator<char>(file)),
                     std::istreambuf_iterator<char>());
    file.close();

    // Parse JSON (simple parsing)
    try {
        weightPcHash = extractWeight(json, "pc_hash");
        weightAge = extractWeight(json, "age");
        weightAccessCount = extractWeight(json, "access_count");
        weightReuseDistance = extractWeight(json, "reuse_distance");
        bias = parseJsonNumber(json, "bias");

        // Override learning parameters if specified in file
        double fileLearningRate = parseJsonNumber(json, "learning_rate");
        if (fileLearningRate > 0.0) {
            learningRate = fileLearningRate;
        }

        bool fileOnlineLearning = parseJsonBool(json, "enable_online_learning");
        enableOnlineLearning = fileOnlineLearning;

        DPRINTF(CacheRepl, "Mockingjay: Loaded weights from %s\n", weightsFile);
    } catch (const std::exception& e) {
        warn("Mockingjay: Error parsing weights file: %s, using defaults\n",
             e.what());
    }
}

double
Mockingjay::computePcHashFeature(Addr pc) const
{
    // Simple hash: take lower bits and normalize to [0, 1]
    // Use modulo 1024 to get a value in [0, 1023], then divide by 1024
    return static_cast<double>(pc % 1024) / 1024.0;
}

double
Mockingjay::computeAgeFeature(Tick insertTick, Tick currentTick) const
{
    if (insertTick == 0 || currentTick <= insertTick) {
        return 0.0;
    }

    Tick age = currentTick - insertTick;

    // Normalize using log scale to handle large tick values
    // log(1 + age) / log(1 + max_reasonable_age)
    // Assume max reasonable age is ~1 billion ticks
    double normalized = std::log(1.0 + static_cast<double>(age)) /
                       std::log(1.0 + 1e9);

    return std::min(normalized, 1.0);
}

double
Mockingjay::computeAccessCountFeature(uint32_t count) const
{
    // Logarithmic scaling: log(1 + count) / log(1001)
    // This maps 0 -> 0, and saturates around 1000 accesses
    return std::log(1.0 + static_cast<double>(count)) / std::log(1001.0);
}

double
Mockingjay::computeReuseDistanceFeature(uint64_t distance) const
{
    // Logarithmic scaling: log(1 + dist) / log(10001)
    // This maps 0 -> 0, and saturates around 10000 distance
    return std::log(1.0 + static_cast<double>(distance)) / std::log(10001.0);
}

double
Mockingjay::computePriority(const MockingjayReplData* data) const
{
    Tick currentTick = curTick();

    double pcHashFeature = computePcHashFeature(data->pc);
    double ageFeature = computeAgeFeature(data->insertTick, currentTick);
    double accessCountFeature = computeAccessCountFeature(data->accessCount);
    double reuseDistFeature = computeReuseDistanceFeature(data->reuseDistance);

    // Linear model: priority = Σ(w_i * f_i) + bias
    double priority = weightPcHash * pcHashFeature +
                      weightAge * ageFeature +
                      weightAccessCount * accessCountFeature +
                      weightReuseDistance * reuseDistFeature +
                      bias;

    return priority;
}

void
Mockingjay::updateWeights(const EvictedEntry& entry, double target)
{
    if (!enableOnlineLearning) {
        return;
    }

    // Compute current prediction
    double prediction = weightPcHash * entry.features[0] +
                       weightAge * entry.features[1] +
                       weightAccessCount * entry.features[2] +
                       weightReuseDistance * entry.features[3] +
                       bias;

    // Gradient descent: w = w - lr * (pred - target) * feature
    double error = prediction - target;

    weightPcHash -= learningRate * error * entry.features[0];
    weightAge -= learningRate * error * entry.features[1];
    weightAccessCount -= learningRate * error * entry.features[2];
    weightReuseDistance -= learningRate * error * entry.features[3];
    bias -= learningRate * error;

    DPRINTF(CacheRepl, "Mockingjay: Updated weights - error: %f, target: %f\n",
            error, target);
}

void
Mockingjay::trackEviction(Addr pc, Tick evictTick, const double features[4]) const
{
    if (!enableOnlineLearning) {
        return;
    }

    // Use simple hash to find slot in eviction table
    size_t index = (pc / 64) % EVICT_TABLE_SIZE;

    evictTable[index].pc = pc;
    evictTable[index].evictTick = evictTick;
    evictTable[index].features[0] = features[0];
    evictTable[index].features[1] = features[1];
    evictTable[index].features[2] = features[2];
    evictTable[index].features[3] = features[3];
    evictTable[index].valid = true;
}

void
Mockingjay::checkEvictedReuse(Addr pc, Tick currentTick)
{
    if (!enableOnlineLearning) {
        return;
    }

    size_t index = (pc / 64) % EVICT_TABLE_SIZE;

    if (evictTable[index].valid && evictTable[index].pc == pc) {
        // This line was evicted and now re-accessed
        // Compute reuse distance in ticks
        Tick reuseTime = currentTick - evictTable[index].evictTick;

        // Target: Lower priority for quickly reused items (negative target)
        // Higher priority for slowly reused items (positive target)
        // Normalize by log scale
        double target = std::log(1.0 + static_cast<double>(reuseTime)) /
                       std::log(1.0 + 1e6) - 0.5;

        updateWeights(evictTable[index], target);

        // Mark as invalid
        evictTable[index].valid = false;
    }
}

void
Mockingjay::invalidate(const std::shared_ptr<ReplacementData>& replacement_data)
{
    std::shared_ptr<MockingjayReplData> casted_replacement_data =
        std::static_pointer_cast<MockingjayReplData>(replacement_data);

    // Reset all fields
    casted_replacement_data->pc = 0;
    casted_replacement_data->insertTick = 0;
    casted_replacement_data->lastTouchTick = 0;
    casted_replacement_data->accessCount = 0;
    casted_replacement_data->reuseDistance = 0;
    casted_replacement_data->lastAccessCounter = 0;
    // Bug #4 Fix: Set priority to max to ensure immediate eviction
    // (higher priority = more likely to evict)
    casted_replacement_data->priority = std::numeric_limits<double>::max();
}

void
Mockingjay::touch(const std::shared_ptr<ReplacementData>& replacement_data,
                  const PacketPtr pkt)
{
    std::shared_ptr<MockingjayReplData> casted_replacement_data =
        std::static_pointer_cast<MockingjayReplData>(replacement_data);

    // Update access count
    casted_replacement_data->accessCount++;

    // Update reuse distance (global accesses since last touch)
    // Bug #1 Fix: Use separate lastAccessCounter field instead of reusing reuseDistance
    if (casted_replacement_data->lastAccessCounter > 0) {
        casted_replacement_data->reuseDistance =
            globalAccessCounter - casted_replacement_data->lastAccessCounter;
    }

    // Update last touch tick and store current access counter
    casted_replacement_data->lastTouchTick = curTick();
    casted_replacement_data->lastAccessCounter = globalAccessCounter;

    // Increment global access counter
    globalAccessCounter++;

    // Extract PC if available
    if (pkt && pkt->req && pkt->req->hasPC()) {
        casted_replacement_data->pc = pkt->req->getPC();

        // Check if this was an evicted entry being re-accessed
        checkEvictedReuse(casted_replacement_data->pc, curTick());
    }

    // Recompute priority
    casted_replacement_data->priority = computePriority(
        casted_replacement_data.get());
}

void
Mockingjay::touch(const std::shared_ptr<ReplacementData>& replacement_data) const
{
    std::shared_ptr<MockingjayReplData> casted_replacement_data =
        std::static_pointer_cast<MockingjayReplData>(replacement_data);

    // Update access count
    casted_replacement_data->accessCount++;

    // Update last touch tick
    casted_replacement_data->lastTouchTick = curTick();

    // Recompute priority (note: this modifies mutable state)
    casted_replacement_data->priority = computePriority(
        casted_replacement_data.get());
}

void
Mockingjay::reset(const std::shared_ptr<ReplacementData>& replacement_data,
                  const PacketPtr pkt)
{
    std::shared_ptr<MockingjayReplData> casted_replacement_data =
        std::static_pointer_cast<MockingjayReplData>(replacement_data);

    // Initialize with current time
    Tick currentTick = curTick();
    casted_replacement_data->insertTick = currentTick;
    casted_replacement_data->lastTouchTick = currentTick;
    casted_replacement_data->accessCount = 0;
    casted_replacement_data->reuseDistance = 0;
    casted_replacement_data->lastAccessCounter = globalAccessCounter;

    // Increment global access counter
    globalAccessCounter++;

    // Extract PC if available
    if (pkt && pkt->req && pkt->req->hasPC()) {
        casted_replacement_data->pc = pkt->req->getPC();

        // Check if this was an evicted entry being re-accessed
        checkEvictedReuse(casted_replacement_data->pc, currentTick);
    } else {
        casted_replacement_data->pc = 0;
    }

    // Compute initial priority
    casted_replacement_data->priority = computePriority(
        casted_replacement_data.get());
}

void
Mockingjay::reset(const std::shared_ptr<ReplacementData>& replacement_data) const
{
    std::shared_ptr<MockingjayReplData> casted_replacement_data =
        std::static_pointer_cast<MockingjayReplData>(replacement_data);

    // Initialize with current time
    Tick currentTick = curTick();
    casted_replacement_data->insertTick = currentTick;
    casted_replacement_data->lastTouchTick = currentTick;
    casted_replacement_data->accessCount = 0;
    casted_replacement_data->pc = 0;

    // Compute initial priority
    casted_replacement_data->priority = computePriority(
        casted_replacement_data.get());
}

ReplaceableEntry*
Mockingjay::getVictim(const ReplacementCandidates& candidates) const
{
    // There must be at least one replacement candidate
    assert(candidates.size() > 0);

    // Bug #2 Fix: First pass - recompute all priorities to ensure they reflect
    // current state (tick/age) rather than stale values from last access
    for (const auto& candidate : candidates) {
        std::shared_ptr<MockingjayReplData> cand_data =
            std::static_pointer_cast<MockingjayReplData>(
                candidate->replacementData);
        cand_data->priority = computePriority(cand_data.get());
    }

    // Second pass: Visit all candidates to find victim with highest priority
    ReplaceableEntry* victim = candidates[0];
    double maxPriority = std::static_pointer_cast<MockingjayReplData>(
        victim->replacementData)->priority;

    for (const auto& candidate : candidates) {
        std::shared_ptr<MockingjayReplData> cand_data =
            std::static_pointer_cast<MockingjayReplData>(
                candidate->replacementData);

        // Update victim entry if this candidate has higher priority
        if (cand_data->priority > maxPriority) {
            victim = candidate;
            maxPriority = cand_data->priority;
        }
    }

    // Track this eviction for online learning
    if (enableOnlineLearning) {
        std::shared_ptr<MockingjayReplData> victim_data =
            std::static_pointer_cast<MockingjayReplData>(
                victim->replacementData);

        double features[4];
        features[0] = computePcHashFeature(victim_data->pc);
        features[1] = computeAgeFeature(victim_data->insertTick, curTick());
        features[2] = computeAccessCountFeature(victim_data->accessCount);
        features[3] = computeReuseDistanceFeature(victim_data->reuseDistance);

        // Bug #3 Fix: No need for const_cast since evictTable is now mutable
        trackEviction(victim_data->pc, curTick(), features);
    }

    return victim;
}

std::shared_ptr<ReplacementData>
Mockingjay::instantiateEntry()
{
    return std::shared_ptr<ReplacementData>(new MockingjayReplData());
}

} // namespace replacement_policy
} // namespace gem5
