//! xtask is a tool for running tasks in the workspace.
fn main() -> Result<(), anyhow::Error> {
    xtaskops::tasks::main()
}
