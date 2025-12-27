/*
 * Unit tests for the standalone GHBHistory helper.
 */

#include <gtest/gtest.h>
#include <vector>

#include "mem/cache/prefetch/ghb_history.hh"

using gem5::prefetch::GHBHistory;

namespace
{

GHBHistory makeHistory(unsigned degree = 2, unsigned confidence = 50,
                       bool use_pc = true)
{
    return GHBHistory(/*history_size=*/16, /*pattern_length=*/4, degree,
                      use_pc, /*page_bytes=*/64, confidence);
}

TEST(GHBHistoryTest, BuildPatternFromPC)
{
    auto history = makeHistory();
    GHBHistory::AccessInfo access;
    access.pc = 0x100;

    access.addr = 0x0;
    history.insert(access);
    access.addr = 0x40;
    history.insert(access);
    access.addr = 0x80;
    int32_t idx = history.insert(access);

    std::vector<int64_t> deltas;
    ASSERT_TRUE(
        history.buildPattern(idx, GHBHistory::CorrelationKey::PC, deltas));
    ASSERT_EQ(deltas.size(), 2U);
    EXPECT_EQ(deltas[0], 0x40);
    EXPECT_EQ(deltas[1], 0x40);
}

TEST(GHBHistoryTest, PageCorrelationWorksWithoutPC)
{
    auto history = makeHistory(/*degree=*/2, /*confidence=*/50, /*use_pc=*/false);
    GHBHistory::AccessInfo access;

    access.addr = 0x100;
    history.insert(access);
    access.addr = 0x108;
    history.insert(access);
    access.addr = 0x110;
    int32_t idx = history.insert(access);

    std::vector<int64_t> deltas;
    ASSERT_TRUE(
        history.buildPattern(idx, GHBHistory::CorrelationKey::Page, deltas));
    EXPECT_EQ(deltas[0], 0x8);
}

TEST(GHBHistoryTest, PatternTablePredictsMostLikelyDelta)
{
    auto history = makeHistory(/*degree=*/2, /*confidence=*/50);
    std::vector<int64_t> chronological = {64, 64, 64, 32, 32, 32};

    history.updatePatternTable(chronological);

    std::vector<int64_t> predicted;
    ASSERT_TRUE(history.findPatternMatch({64, 64}, predicted));
    ASSERT_EQ(predicted.size(), 1U);
    EXPECT_TRUE(predicted[0] == 64 || predicted[0] == 32);

    ASSERT_TRUE(history.findPatternMatch({32, 32}, predicted));
    ASSERT_EQ(predicted.size(), 1U);
    EXPECT_EQ(predicted[0], 32);
}

TEST(GHBHistoryTest, FallbackUsesRecentDeltas)
{
    auto history = makeHistory(/*degree=*/3);
    std::vector<int64_t> predicted;
    std::vector<int64_t> chronological = {16, 8, 4};

    history.fallbackPattern(chronological, predicted);
    ASSERT_EQ(predicted.size(), 1U);
    EXPECT_EQ(predicted[0], 4);
}

} // anonymous namespace
