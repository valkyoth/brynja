use super::{Error, platform};

/// Resident, dump-excluded native execution stack with inaccessible guards.
///
/// `run` starts one fresh native thread and joins it before returning. Its stack
/// is cleared from the calling thread after termination, including recoverable
/// unwind. There is no detachable/forgettable join handle. The resource is not
/// Send/Sync/Copy/Clone/Debug and never exposes its stack bytes.
///
/// This is NOT strict cryptographic admission or a secure-closure sandbox.
/// Captures remain caller-owned before launch, and unrelated heap allocations,
/// dynamically allocated TLS, signal-handler stacks, panic hooks, registers and
/// caller copies are outside this guarantee. In particular do not treat moving
/// a secret-bearing value into a closure as erasing its original copy. A future
/// strict executor must constrain those paths separately. Fork, external native
/// cancellation, and externally revoking memory protections are unsupported.
///
/// Stack overflow, aborting panic, panic while dropping a panic payload and an
/// unexpected native join/attribute-destruction failure terminate the process;
/// no cleanup on fatal termination is promised. Join failure cannot return safely while a callback
/// may still borrow the caller. No weaker worker is substituted on failure.
///
/// ```no_run
/// use brynja_crypto_cpu_std::protected_memory::{Error, ProtectedBytes, ProtectedStack};
/// fn scoped_work() -> Result<(), Error> {
///     let mut output = ProtectedBytes::new(32, 65536)?;
///     let mut stack = ProtectedStack::new(262144, 1048576)?;
///     let destination = output.as_bytes_mut();
///     stack.run(move || destination.fill(0x58))?;
///     // Output stays in its separate protected owner after the worker joins.
///     output.clear();
///     stack.close().map_err(|(error, _cleared_owner)| error)?;
///     output.close().map_err(|(error, _cleared_owner)| error)
/// }
/// ```
///
/// ```compile_fail
/// use brynja_crypto_cpu_std::protected_memory::ProtectedStack;
/// fn require<T: Send>() {}
/// require::<ProtectedStack>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu_std::protected_memory::ProtectedStack;
/// let mut stack = ProtectedStack::new(262144, 1048576).unwrap();
/// let not_send = std::rc::Rc::new(1);
/// stack.run(move || drop(not_send)).unwrap();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu_std::protected_memory::ProtectedStack;
/// fn require<T: Sync>() {}
/// require::<ProtectedStack>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu_std::protected_memory::ProtectedStack;
/// fn require<T: Clone>() {}
/// require::<ProtectedStack>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu_std::protected_memory::ProtectedStack;
/// fn require<T: Copy>() {}
/// require::<ProtectedStack>();
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu_std::protected_memory::ProtectedStack;
/// fn require<T: core::fmt::Debug>() {}
/// require::<ProtectedStack>();
/// ```
pub struct ProtectedStack {
    mapping: platform::Mapping,
    _local: core::marker::PhantomData<std::rc::Rc<()>>,
}

impl ProtectedStack {
    /// Preacquires a stack, before the resource receives a callback or inputs.
    ///
    /// At least 64 KiB is required; this is a floor, not a sufficient size for
    /// every job. The native thread runtime also consumes part of this mapping.
    /// The total bound includes page rounding and two guard pages, just as for
    /// [`super::ProtectedBytes`]. Unsupported adapters return Unsupported.
    pub fn new(stack_bytes: usize, max_mapping_bytes: usize) -> Result<Self, Error> {
        Ok(Self {
            mapping: platform::Mapping::stack(stack_bytes, max_mapping_bytes)?,
            _local: core::marker::PhantomData,
        })
    }

    /// Runs one borrowed callback on this stack, joins, then clears the stack.
    ///
    /// The callback returns no value through native thread storage. Use explicit
    /// borrowed output resources; their protection remains a separate obligation.
    /// Non-Send captures are rejected. There is no timeout/forced cancellation:
    /// the callback must finish or unwind before borrowed resources can return.
    /// The cleared stack can be reused after success or a caught callback panic.
    pub fn run<F: FnOnce() + Send>(&mut self, work: F) -> Result<(), Error> {
        self.mapping.run(work)
    }

    /// Releases the inactive, cleared stack; retains the owner on release error.
    pub fn close(mut self) -> Result<(), (Error, Self)> {
        match self.mapping.close() {
            Ok(()) => Ok(()),
            Err(error) => Err((error, self)),
        }
    }
}
