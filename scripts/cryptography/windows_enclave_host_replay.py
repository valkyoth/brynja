"""Translate source-bound public native wire records into LOCAL Rust model tests.

This does not execute an enclave and cannot create fresh native evidence.
"""
import hashlib
import json
from pathlib import Path
import subprocess

import windows_enclave_wire as wire

ROOT = Path(__file__).resolve().parents[2]
COMMIT = '53ec2efe1b39d70619b1f0b530f5d1865fc421f8'
OBSERVATIONS = ROOT / 'assurance/windows-protection-observations'


def records():
    source_hashes = {name: hashlib.sha256(subprocess.check_output(
        ['git', 'show', COMMIT + ':' + name], cwd=ROOT)).hexdigest() for name in wire.SOURCES}
    result = []
    for mode in wire.MODES:
        path = OBSERVATIONS / ('window-wire-' + mode + '-53ec2efe.json')
        record = json.loads(path.read_text())
        if record['commit'] != COMMIT or record['source_sha256'] != source_hashes:
            raise ValueError('native replay source binding changed')
        fields = list(wire.previous.guard.NONCLAIMS) + ['synthetic_only', 'deleted', 'native_machine', 'mode', 'calls', 'donor']
        wire.validate_record({key: record[key] for key in fields}, mode)
        result.append((mode, record['calls']))
        if record['donor']:
            result.append(('publish', record['donor']['calls']))
    return result


def rust_test():
    calls = []
    for mode, items in records():
        for iteration, item in enumerate(items):
            offers = '&[' + ','.join('[' + ','.join(str(n) for n in offer) + ']' for offer in item['offers']) + ']'
            digest = ('Some(&[' + ','.join(str(b) for b in bytes.fromhex(item['digest'])) + '])'
                      if item['digest'] is not None else 'None')
            first, _, _, _, _, cleared, second, _ = item['wire']
            calls.append(f'replay({iteration}, {str(mode == "cancel").lower()}, {offers}, {digest}, '
                         f'{first}, {second}, {str(cleared == 1).lower()}, '
                         f'{str(item["values"][6] == 1).lower()});')
    if len(calls) != 42:
        raise ValueError('expected all 42 native call transcripts, including donor')
    return '''
#[cfg(test)]
mod native_transcript_replay {
    use super::*;
    fn replay(iteration: u64, cancel: bool, offers: &[[u64;8]], digest: Option<&[u8;32]>,
              first: u64, second: u64, cleared: bool, outer_clear: bool) {
        // Each transcript is replayed independently at its recorded epoch.
        // Runtime tests separately establish persistent session quarantine/reuse.
        let mut session = Session::new();
        session.epoch = iteration;
        if iteration != 0 && !offers.is_empty() {
            session.namespace = Some([offers[0][0], offers[0][1]]);
        }
        let mut output = [0xa5;32];
        let disposition = if cancel { Disposition::Cancel } else { Disposition::ExportPublic(&mut output) };
        let mut pending = session.prepare(PublicInput::acknowledge(b"public replay"), disposition).unwrap();
        pending.enter(1000, if cancel {0} else {2000}).unwrap();
        let mut rejected = false;
        for (index, offer) in offers.iter().enumerate() {
            if pending.offer(&wire::encode(*offer)).is_err() {
                rejected = true;
                break;
            }
            if index == 0 { if let Some(bytes) = digest { pending.receive_public(bytes).unwrap(); } }
        }
        let completed = !rejected && offers.len() == 2 && second == 21 && matches!(first,1|2|12);
        if completed {
            let expected = match first {1=>Ok(Outcome::Exported),2=>Ok(Outcome::Cancelled),_=>Err(Error::Copy)};
            assert_eq!(pending.finish(first, second, cleared, outer_clear), expected);
        } else if !rejected {
            assert_eq!(pending.finish(first, second, cleared, outer_clear), Err(Error::Protocol));
        }
        drop(pending);
        assert_eq!(session.state(), if completed {State::Ready} else {State::Quarantined});
        assert_eq!(output, if completed && first == 1 {*digest.unwrap()} else {[0xa5;32]});
    }
    #[test]
    fn recorded_native_calls_replayed_locally_not_native_execution() {
''' + '\n'.join('        ' + call for call in calls) + '\n    }\n}\n'
