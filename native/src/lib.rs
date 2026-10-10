use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[derive(Clone, Copy, PartialEq)]
struct Network {
    version: u8,
    start: u128,
    end: u128,
}

impl Network {
    fn new(version: u8, start: u128, prefix: u8) -> PyResult<Self> {
        let bits = match version {
            4 => 32,
            6 => 128,
            _ => return Err(PyValueError::new_err("expected IPv4 or IPv6")),
        };
        if prefix > bits || (version == 4 && start > u32::MAX.into()) {
            return Err(PyValueError::new_err("invalid network address or prefix"));
        }
        let host_bits = bits - prefix;
        let host_mask = if host_bits == 128 {
            u128::MAX
        } else {
            (1_u128 << host_bits) - 1
        };
        if start & host_mask != 0 {
            return Err(PyValueError::new_err("network address has host bits set"));
        }
        Ok(Self {
            version,
            start,
            end: start | host_mask,
        })
    }

    fn contains(self, other: Self) -> bool {
        self.version == other.version && self.start <= other.start && self.end >= other.end
    }
}

fn select(networks: &[Network], existing: usize) -> Vec<usize> {
    let mut selected: Vec<usize> = (0..existing).collect();
    for next in existing..networks.len() {
        let address = networks[next];
        let mut matched = false;
        for &index in &selected {
            let previous = networks[index];
            if previous.contains(address) {
                matched = true;
                break;
            }
            if address.contains(previous) {
                // SRX replaces only the first overlapping network (and its
                // duplicates). Later contained networks keep their positions.
                for index in &mut selected {
                    if networks[*index] == previous {
                        *index = next;
                    }
                }
                matched = true;
                break;
            }
        }
        if !matched {
            selected.push(next);
        }
    }
    selected
}

#[pyfunction]
fn address_book_indices(networks: Vec<(u8, u128, u8)>, existing: usize) -> PyResult<Vec<usize>> {
    if existing > networks.len() {
        return Err(PyValueError::new_err(
            "existing count exceeds network count",
        ));
    }
    let networks: Vec<Network> = networks
        .into_iter()
        .map(|(version, start, prefix)| Network::new(version, start, prefix))
        .collect::<PyResult<_>>()?;
    Ok(select(&networks, existing))
}

#[pymodule]
fn _capirca_native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(address_book_indices, module)?)
}
