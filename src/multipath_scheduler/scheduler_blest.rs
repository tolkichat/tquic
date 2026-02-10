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

/// BLEST (BLocking ESTimation) scheduler aims to minimize Head-of-Line (HoL)
/// blocking by estimating when a slower path might cause the receiver to stall.
///
/// The key insight is that sending data on a slow path can cause blocking at
/// the receiver if the data arrives after subsequent data sent on a faster path.
/// BLEST estimates the blocking potential of each path and prefers paths that
/// minimize this risk.
///
/// Reference: "BLEST: Blocking Estimation-based MPTCP Scheduler for
/// Heterogeneous Networks" (Ferlin et al.)
pub struct BlestScheduler {
    /// Lambda parameter controlling the blocking estimation threshold.
    /// Higher values make the scheduler more aggressive in avoiding slow paths.
    lambda: f64,

    /// Track bytes in flight per path for blocking estimation
    bytes_in_flight: Vec<(usize, u64)>,

    /// Fallback path when BLEST estimation rejects all paths
    fallback_path: Option<usize>,
}

impl BlestScheduler {
    pub fn new(conf: &MultipathConfig) -> BlestScheduler {
        BlestScheduler {
            lambda: conf.blest_lambda,
            bytes_in_flight: Vec::new(),
            fallback_path: None,
        }
    }

    /// Estimate the completion time for data on a given path.
    /// completion_time = srtt + (bytes_in_flight / bandwidth)
    fn estimate_completion_time(srtt: Duration, cwnd: u64, bytes_in_flight: u64) -> Duration {
        let srtt_ms = srtt.as_millis() as u64;
        if srtt_ms == 0 || cwnd == 0 {
            return srtt;
        }

        // Estimate bandwidth as cwnd / srtt
        let bandwidth = cwnd.saturating_mul(1000) / srtt_ms;
        if bandwidth == 0 {
            return srtt;
        }

        // Time to drain current bytes in flight
        let drain_time_ms = bytes_in_flight.saturating_mul(1000) / bandwidth;
        srtt + Duration::from_millis(drain_time_ms)
    }

    /// Calculate the blocking potential of a path.
    /// A path has high blocking potential if its completion time exceeds
    /// the fastest path's completion time by more than lambda * min_rtt.
    fn calculate_blocking_potential(
        path_completion: Duration,
        min_completion: Duration,
        min_rtt: Duration,
        lambda: f64,
    ) -> bool {
        let threshold = Duration::from_secs_f64(min_rtt.as_secs_f64() * lambda);
        path_completion > min_completion + threshold
    }
}

impl MultipathScheduler for BlestScheduler {
    /// Select a path that minimizes blocking potential.
    ///
    /// The algorithm:
    /// 1. Calculate completion time for each active path
    /// 2. Find the minimum completion time
    /// 3. Select paths whose completion time doesn't exceed the blocking threshold
    /// 4. Among eligible paths, prefer the one with minimum completion time
    fn on_select(
        &mut self,
        paths: &mut PathMap,
        _spaces: &mut PacketNumSpaceMap,
        _streams: &mut StreamMap,
    ) -> Result<usize> {
        let mut candidates: Vec<(usize, Duration, Duration)> = Vec::new();

        // Gather completion times and RTTs for all active paths
        for (pid, path) in paths.iter_mut() {
            if !path.active() || !path.recovery.can_send() {
                continue;
            }

            let cwnd = path.recovery.congestion.congestion_window();
            let srtt = path.recovery.rtt.smoothed_rtt();
            let bytes_in_flight = path.recovery.bytes_in_flight as u64;

            let completion_time = Self::estimate_completion_time(srtt, cwnd, bytes_in_flight);
            candidates.push((pid, completion_time, srtt));
        }

        if candidates.is_empty() {
            return Err(Error::Done);
        }

        // Find minimum completion time and minimum RTT
        let min_completion = candidates
            .iter()
            .map(|(_, ct, _)| *ct)
            .min()
            .unwrap_or(Duration::ZERO);
        let min_rtt = candidates
            .iter()
            .map(|(_, _, rtt)| *rtt)
            .min()
            .unwrap_or(Duration::from_millis(1));

        // Filter out paths with high blocking potential
        let eligible: Vec<_> = candidates
            .iter()
            .filter(|(_, completion, _)| {
                !Self::calculate_blocking_potential(
                    *completion,
                    min_completion,
                    min_rtt,
                    self.lambda,
                )
            })
            .collect();

        // If all paths have high blocking potential, use the fastest one anyway
        if eligible.is_empty() {
            // Find path with minimum completion time
            let best = candidates
                .iter()
                .min_by_key(|(_, ct, _)| *ct)
                .map(|(pid, _, _)| *pid);
            self.fallback_path = best;
            return best.ok_or(Error::Done);
        }

        // Among eligible paths, select the one with minimum completion time
        // (which also tends to be the one with lowest blocking potential)
        let best = eligible
            .iter()
            .min_by_key(|(_, ct, _)| *ct)
            .map(|(pid, _, _)| *pid);

        self.fallback_path = best;
        best.ok_or(Error::Done)
    }

    /// Track bytes in flight for blocking estimation.
    fn on_sent(
        &mut self,
        packet: &SentPacket,
        _now: Instant,
        path_id: usize,
        _paths: &mut PathMap,
        _spaces: &mut PacketNumSpaceMap,
        _streams: &mut StreamMap,
    ) {
        // Track sent bytes per path for more accurate blocking estimation
        if let Some(entry) = self
            .bytes_in_flight
            .iter_mut()
            .find(|(pid, _)| *pid == path_id)
        {
            entry.1 = entry.1.saturating_add(packet.sent_size as u64);
        } else {
            self.bytes_in_flight
                .push((path_id, packet.sent_size as u64));
        }
    }

    /// Update tracking when path events occur.
    fn on_path_updated(&mut self, _paths: &mut PathMap, event: PathEvent) {
        match event {
            PathEvent::Closed(path_id) | PathEvent::Failed(path_id) => {
                // Remove tracking for closed/failed paths
                self.bytes_in_flight.retain(|(pid, _)| *pid != path_id);
                if self.fallback_path == Some(path_id) {
                    self.fallback_path = None;
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multipath_scheduler::tests::MultipathTester;

    #[test]
    fn blest_single_path() -> Result<()> {
        let mut t = MultipathTester::new()?;

        let mut s = BlestScheduler::new(&MultipathConfig::default());
        assert_eq!(s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?, 0);
        assert_eq!(s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?, 0);
        Ok(())
    }

    #[test]
    fn blest_prefers_faster_path() -> Result<()> {
        let mut t = MultipathTester::new()?;
        // Add a much faster path - BLEST should prefer it to avoid blocking
        t.add_path("127.0.0.1:443", "127.0.0.2:8443", 20)?; // Very fast path
        t.add_path("127.0.0.1:443", "127.0.0.3:8443", 500)?; // Very slow path

        let mut s = BlestScheduler::new(&MultipathConfig::default());

        // The fast path should be selected to minimize blocking
        let mut fast_path_count = 0;
        for _ in 0..10 {
            let pid = s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?;
            if pid == 1 {
                // Path 1 is the 20ms path
                fast_path_count += 1;
            }
        }

        // Fast path should be selected most of the time
        assert!(fast_path_count >= 7);

        Ok(())
    }

    #[test]
    fn blest_similar_paths() -> Result<()> {
        let mut t = MultipathTester::new()?;
        // Add paths with similar RTTs - both should be usable
        t.add_path("127.0.0.1:443", "127.0.0.2:8443", 50)?;
        t.add_path("127.0.0.1:443", "127.0.0.3:8443", 60)?;

        let mut s = BlestScheduler::new(&MultipathConfig::default());

        // Both paths should be eligible
        let mut path_counts = [0u32; 4];
        for _ in 0..20 {
            let pid = s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams)?;
            path_counts[pid] += 1;
        }

        // The faster path (50ms) should be preferred but both can be used
        assert!(path_counts[1] >= path_counts[2]);

        Ok(())
    }

    #[test]
    fn blest_no_available_path() -> Result<()> {
        let mut t = MultipathTester::new()?;
        t.set_path_active(0, false)?;

        let mut s = BlestScheduler::new(&MultipathConfig::default());
        assert_eq!(
            s.on_select(&mut t.paths, &mut t.spaces, &mut t.streams),
            Err(Error::Done)
        );
        Ok(())
    }
}
