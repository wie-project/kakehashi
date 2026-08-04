## Description
Please include a summary of the change. If you are fixing a bug or adding a new syscall translation to `kh-runtime`, please describe your approach and layout alignment considerations.

## Checklist Before Submitting
- [ ] My code follows clean-room (light-grey) design
- [ ] I have run `cargo test` and all tests passed (including kh-libsystem)
- [ ] I have run `cargo clippy` and fixed any warnings (including kh-libsystem)
- [ ] If I have used AI in development, I closely monitored and managed the process
- [ ] I have tested on arm64
- [ ] I have verified the changes locally across **BOTH** environments (as behavior may vary):
  - [ ] **Docker container** (Specify distro/kernel: e.g., Ubuntu 24.04, kernel 6.8)
  - [ ] **UTM / Other VM** or native hardware (Specify distro/kernel: e.g., Asahi Linux, kernel 6.12)
