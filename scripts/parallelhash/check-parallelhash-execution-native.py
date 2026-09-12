#!/usr/bin/env python3
"""Release-only native evidence gate; ordinary CI does not require collected lanes."""
import parallelhash_execution_native

if __name__ == '__main__':
    parallelhash_execution_native.validate()
