// Copyright (c) 2023 The TQUIC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::time::Duration;
use std::time::Instant;

use crate::connection::path::PathMap;
use crate::connection::space::PacketNumSpaceMap;
use crate::connection::space::SentPacket;
use crate::connection::stream::StreamMap;
use crate::multipath_scheduler::MultipathScheduler;
use crate::Error;
use crate::MultipathConfig;
use crate::PathEvent;
use crate::Result;

/// WeightedScheduler distributes packets across paths proportionally to their
/// estimated bandwidth capacity.
///
/// The scheduler estimates bandwidth using the congestion window and RTT of each
/// path. Paths with higher bandwidth get proportionally more packets. This
/// approach aims to maximize aggregate throughput by utilizing each path
/// according to its capacity.
///
/// Weight calculation: weight = cwnd / srtt
/// This gives a bandwidth estimate in bytes per second.
pub struct WeightedScheduler {
    /// Accumulated weights for weighted selection
    accumulated_weights: Vec<(usize, u64)>,
    /// Counter for weighted round-robin selection
    counter: u64,
    /// Total weight across all paths
    total_weight: u64,
}

impl WeightedScheduler {
    pub fn new(_conf: &MultipathConfig) -> WeightedScheduler {
        WeightedScheduler {
            accumulated_weights: Vec::new(),
            counter: 0,
            total_weight: 0,
        }
    }

    /// Calculate the weight for a path based on its bandwidth estimate.
    /// Weight = cwnd / srtt (bandwidth estimate)
    fn calculate_weight(cwnd: u64, srtt: Duration) -> u64 {
        let srtt_ms = srtt.as_millis() as u64;
        if srtt_ms == 0 {
            return cwnd;
        }
        // Scale by 1000 to maintain precision with integer arithmetic
        // This gives weight in "bytes per millisecond" units
        cwnd.saturating_mul(1000) / srtt_ms
    }
}

impl MultipathScheduler for WeightedScheduler {
    /// Select a path based on weighted bandwidth distribution.
    /// Paths with higher bandwidth estimates receive proportionally more packets.
    fn on_select(
        &mut self,
        paths: &mut PathMap,
        _spaces: &mut PacketNumSpaceMap,
        _streams: &mut StreamMap,
    ) -> Result<usize> {
        // Rebuild weights on each selection to handle dynamic path changes
        self.accumulated_weights.clear();
        self.total_weight = 0;

        // Calculate raw weights for all active paths with available congestion window
        let mut raw_weights: Vec<(usize, u64)> = Vec::new();
        let mut min_weight = u64::MAX;

        for (pid, path) in paths.iter_mut() {
            if !path.active() || !path.recovery.can_send() {
                continue;
            }

            let cwnd = path.recovery.congestion.congestion_window();
            let srtt = path.recovery.rtt.smoothed_rtt();
            let weight = Self::calculate_weight(cwnd, srtt);

            if weight > 0 {
                min_weight = min_weight.min(weight);
                raw_weights.push((pid, weight));
            }
        }

        if raw_weights.is_empty() {
            return Err(Error::Done);
        }

        // Normalize weights relative to the smallest weight to keep counter manageable
        let divisor = min_weight.max(1);
        for (pid, weight) in &raw_weights {
            let normalized = (*weight / divisor).max(1);
            self.total_weight = self.total_weight.saturating_add(normalized);
            self.accumulated_weights.push((*pid, self.total_weight));
        }

        // Use counter-based weighted selection for fair distribution
        self.counter = self.counter.wrapping_add(1);
        let target = self.counter % self.total_weight;

        // Find the path whose accumulated weight range contains the target
        for (pid, acc_weight) in &self.accumulated_weights {
            if target < *acc_weight {
                return Ok(*pid);
            }
        }

        // Fallback to last path (shouldn't normally happen)
        Ok(self.accumulated_weights.last().unwrap().0)
    }

    /// Update weights when path metrics change significantly.
    fn on_path_updated(&mut self, _paths: &mut PathMap, _event: PathEvent) {
        // Weights are recalculated on each selection, so no action needed here
    }

    /// Track sent packets for potential weight adjustment.
    fn on_sent(
        &mut self,
        _packet: &SentPacket,
        _now: Instant,
        _path_id: usize,
        _paths: &mut PathMap,
        _spaces: &mut PacketNumSpaceMap,
        _streams: &mut StreamMap,
    ) {
        // No additional tracking needed for basic weighted scheduling
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multipath_scheduler::tests::MultipathTester;

    #[test]
    fn weighted_single_path() -> Result<()> {
        let mut t = MultipathTester::new()?;

        let mut s = WeightedScheduler::new(&MultipathConfig::default());
        assert_eq!(s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?, 0);
        assert_eq!(s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?, 0);
        Ok(())
    }

    #[test]
    fn weighted_multi_path() -> Result<()> {
        let mut t = MultipathTester::new()?;
        // Add paths with different RTTs - lower RTT should get higher weight
        t.add_path("127.0.0.1:443", "127.0.0.2:8443", 50)?; // Faster path
        t.add_path("127.0.0.1:443", "127.0.0.3:8443", 200)?; // Slower path

        let mut s = WeightedScheduler::new(&MultipathConfig::default());

        // With different RTTs, the faster path (lower RTT) should be selected more often
        let mut path_counts = [0u32; 4];
        for _ in 0..100 {
            let pid = s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?;
            path_counts[pid] += 1;
        }

        // Verify that faster path (pid 1, 50ms RTT) is selected more than slower paths
        // Path 0: 200ms, Path 1: 50ms, Path 2: 200ms
        // Normalized weights: 1:4:1, so path 1 should get ~66% of selections
        assert!(path_counts[1] > path_counts[0]);
        assert!(path_counts[1] > path_counts[2]);

        Ok(())
    }

    #[test]
    fn weighted_no_available_path() -> Result<()> {
        let mut t = MultipathTester::new()?;
        t.set_path_active(0, false)?;

        let mut s = WeightedScheduler::new(&MultipathConfig::default());
        assert_eq!(
            s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams),
            Err(Error::Done)
        );
        Ok(())
    }

    #[test]
    fn weighted_path_deactivation() -> Result<()> {
        let mut t = MultipathTester::new()?;
        t.add_path("127.0.0.1:443", "127.0.0.2:8443", 50)?;

        let mut s = WeightedScheduler::new(&MultipathConfig::default());

        // Both paths should be selectable
        let pid1 = s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?;
        assert!(pid1 == 0 || pid1 == 1);

        // Deactivate path 1
        t.set_path_active(1, false)?;

        // Only path 0 should be selected
        for _ in 0..10 {
            assert_eq!(s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?, 0);
        }

        Ok(())
    }
}
