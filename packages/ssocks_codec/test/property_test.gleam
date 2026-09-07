//// The properties, at the size that belongs in an ordinary test run.
////
//// The seed is fixed so this is the same test every time. `mise run
//// test-property` runs the same properties far longer, and any failure there
//// reports a seed that reproduces it exactly.

// SPDX-FileCopyrightText: 2026 ssocks contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

import properties
import qcheck

pub fn every_property_holds_test() {
  properties.check_all(qcheck.config(
    test_count: 200,
    max_retries: 1,
    seed: qcheck.seed(20_260_907),
  ))
}
