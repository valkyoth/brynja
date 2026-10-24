"""Independent byte HMAC and separate Python bit-model controls per MD5 lane."""
import hashlib
import hmac

import legacy_hmac_bits


def expected():
    digest = legacy_hmac_bits.model("md5")
    rows = {}
    for key_shape in range(4):
        for message_shape in range(3):
            for rotation in range(8):
                for lane in range(8):
                    key_id, message_id = (lane + rotation) % 8, (lane + 2 * rotation) % 8
                    length = (64, 65, (0, 1, 63, 64, 65, 80, 129, 1024)[key_id], 129)[key_shape]
                    bits = (1024, (0, 1, 55, 56, 63, 64, 65, 129)[message_id] * 8,
                            (1, 7, 8, 9, 447, 448, 511, 513)[message_id])[message_shape]
                    key = bytes((index * 29 + key_id * 37 + key_shape * 11 + 1) % 256 for index in range(length))
                    message = bytearray((index * 29 + message_id * 37 + (message_shape + 4) * 11 + 1) % 256
                                        for index in range((bits + 7) // 8))
                    if bits % 8:
                        message[-1] &= (255 << (8 - bits % 8)) & 255
                    pad = (digest(key, length * 8) if length > 64 else key).ljust(64, b"\0")
                    inner = digest(bytes(byte ^ 0x36 for byte in pad) + message, 512 + bits)
                    tag = digest(bytes(byte ^ 0x5c for byte in pad) + inner, 640)
                    if bits % 8 == 0 and tag != hmac.new(key, message, hashlib.md5).digest():
                        raise ValueError("MD5 lane bit model disagrees with independent byte HMAC")
                    rows[f"{key_shape}:{message_shape}:{rotation}:{lane}"] = tag.hex()
    if len(rows) != 768:
        raise ValueError("MD5 lane oracle population changed")
    return rows
