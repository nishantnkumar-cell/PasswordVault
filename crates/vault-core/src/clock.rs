//! Version vectors for merging copies of a vault (section 5.1).

use serde::{Deserialize, Serialize};

/// Identifies one writer of a vault, such as one `vaultd`. Chosen at random
/// once per installation and kept outside the vault file.
pub type DeviceId = u64;

/// How two clocks relate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Order {
    Equal,
    Before,
    After,
    Concurrent,
}

/// A version vector: for each device, how many edits it has made. Kept
/// sorted by device, without zero counters, so equal clocks encode equally.
#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq, Eq)]
pub(crate) struct Clock(Vec<(DeviceId, u64)>);

impl Clock {
    /// Restore the invariants after decoding: sorted, unique, no zeros.
    pub(crate) fn normalized(mut self) -> Clock {
        self.0.retain(|&(_, n)| n > 0);
        self.0.sort_unstable();
        self.0.dedup_by(|b, a| {
            if a.0 == b.0 {
                a.1 = a.1.max(b.1);
                true
            } else {
                false
            }
        });
        self
    }

    fn get(&self, device: DeviceId) -> u64 {
        self.0
            .binary_search_by_key(&device, |&(d, _)| d)
            .map_or(0, |i| self.0[i].1)
    }

    /// Record one more edit by `device`.
    pub(crate) fn bump(&mut self, device: DeviceId) {
        match self.0.binary_search_by_key(&device, |&(d, _)| d) {
            Ok(i) => self.0[i].1 = self.0[i].1.saturating_add(1),
            Err(i) => self.0.insert(i, (device, 1)),
        }
    }

    /// The smallest clock at or after both.
    pub(crate) fn join(&self, other: &Clock) -> Clock {
        let mut out = self.clone();
        for &(d, n) in &other.0 {
            match out.0.binary_search_by_key(&d, |&(e, _)| e) {
                Ok(i) => out.0[i].1 = out.0[i].1.max(n),
                Err(i) => out.0.insert(i, (d, n)),
            }
        }
        out
    }

    pub(crate) fn compare(&self, other: &Clock) -> Order {
        let mut less = false;
        let mut more = false;
        for &(d, _) in self.0.iter().chain(&other.0) {
            let (a, b) = (self.get(d), other.get(d));
            less |= a < b;
            more |= a > b;
        }
        match (less, more) {
            (false, false) => Order::Equal,
            (true, false) => Order::Before,
            (false, true) => Order::After,
            (true, true) => Order::Concurrent,
        }
    }

    /// Whether every edit this clock records is also in `other`.
    pub(crate) fn le(&self, other: &Clock) -> bool {
        matches!(self.compare(other), Order::Equal | Order::Before)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(v: &[(DeviceId, u64)]) -> Clock {
        Clock(v.to_vec()).normalized()
    }

    #[test]
    fn order() {
        let a = c(&[(1, 2)]);
        assert_eq!(a.compare(&a), Order::Equal);
        assert_eq!(c(&[]).compare(&a), Order::Before);
        assert_eq!(c(&[(1, 2), (2, 1)]).compare(&a), Order::After);
        assert_eq!(c(&[(1, 1), (2, 1)]).compare(&a), Order::Concurrent);
        assert!(a.le(&a.join(&c(&[(2, 1)]))));
    }

    #[test]
    fn bump_and_normalize() {
        let mut a = c(&[(5, 1), (2, 0), (3, 4), (3, 2)]);
        assert_eq!(a, Clock(vec![(3, 4), (5, 1)]));
        a.bump(4);
        a.bump(5);
        assert_eq!(a, Clock(vec![(3, 4), (4, 1), (5, 2)]));
    }
}
