#!/usr/bin/env python3
"""Prepare the ignored authority cache from reviewed local PDF/RFC sources."""
import lifecycle_local as local
import lifecycle_model as model


if __name__ == "__main__":
    register = model.load_json(model.REGISTER)
    model.validate_register(register)
    count = local.prepare(register, model.read_policy())
    print(f"Verified local authority cache: {count} documents; no network or repinning")
