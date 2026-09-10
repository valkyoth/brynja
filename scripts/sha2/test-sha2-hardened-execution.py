#!/usr/bin/env python3
"""Negative policy fixtures for secret-bearing SHA-2 execution."""
import sha2_hardened_execution_policy as policy

if __name__ == '__main__':
    policy.validate()
    policy.regressions()
