"""Example usage of the security tool adapters.

This script demonstrates how to use the Heimdall, Trident, and Cargo Audit adapters.
"""

import asyncio

from vulnhunter.adapters import HeimdallAdapter, TridentAdapter, CargoAuditAdapter


async def example_heimdall():
    """Example: Decompile an Ethereum contract with Heimdall."""
    adapter = HeimdallAdapter()

    if not adapter.is_available():
        print("Heimdall not installed. Install with: cargo install heimdall")
        return

    # Example: Decompile a deployed contract
    contract_address = "0x7a250d5630b4cf539739df2c5dacb4c659f2488d"
    findings = await adapter.run(contract_address)

    print(f"Found {len(findings)} findings:")
    for finding in findings:
        print(f"  - {finding.title} ({finding.severity})")
        print(f"    Location: {finding.location}")
        print(f"    Description: {finding.description[:100]}...")
        print()


async def example_trident():
    """Example: Fuzz a Solana program with Trident."""
    adapter = TridentAdapter()

    if not adapter.is_available():
        print("Trident not installed. Install with: cargo install trident")
        return

    # Example: Run fuzzing on a target program
    target = "target_program"
    findings = await adapter.run(target)

    print(f"Found {len(findings)} findings:")
    for finding in findings:
        print(f"  - {finding.title} ({finding.severity})")
        if finding.title == "Trident crash":
            print(f"    CRASH DETECTED!")
        print()


async def example_cargo_audit():
    """Example: Audit Rust dependencies with cargo-audit."""
    adapter = CargoAuditAdapter()

    if not adapter.is_available():
        print("cargo-audit not installed. Install with: cargo install cargo-audit")
        return

    # Example: Audit current directory
    project_path = "."
    findings = await adapter.run(project_path)

    print(f"Found {len(findings)} findings:")
    for finding in findings:
        print(f"  - {finding.title} ({finding.severity})")
        print(f"    Location: {finding.location}")
        print()


async def main():
    """Run all examples."""
    print("=" * 60)
    print("Heimdall Adapter Example")
    print("=" * 60)
    await example_heimdall()

    print("\n" + "=" * 60)
    print("Trident Adapter Example")
    print("=" * 60)
    await example_trident()

    print("\n" + "=" * 60)
    print("Cargo Audit Adapter Example")
    print("=" * 60)
    await example_cargo_audit()


if __name__ == "__main__":
    asyncio.run(main())
