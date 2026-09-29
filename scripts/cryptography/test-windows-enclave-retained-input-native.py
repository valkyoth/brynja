#!/usr/bin/env python3
"""Mocked orchestration and tamper rejection, not native evidence."""
import copy
import ctypes as c
import hashlib
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch
import windows_enclave_retained_input_native as model
from windows_protection_probe import ProbeError

spec=importlib.util.spec_from_file_location('retained_tests',Path(__file__).with_name('test-windows-enclave-retained-native.py'))
support=importlib.util.module_from_spec(spec);spec.loader.exec_module(support)


class Api(support.Api):
    def __init__(self):
        super().__init__();self.input_report=[0]*11;self.epoch=0
    def GetProcAddress(self,base,name):
        return {b'PublicRetainedInput':7,b'PublicInputControl':8}.get(name,super().GetProcAddress(base,name))
    def call(self,routine,op):
        if routine==7:
            self.input_report=[0]*11;return 1
        if routine==8:return self.input_report[op-16]
        return super().call(routine,op)
    def work(self,operation,callback):
        step=model.campaign()[self.index];self.index+=1
        op,status,live,index,fault=step;assert op==operation
        region,data=support.support.REGION,support.support.DATA
        if op==0:
            self.epoch+=1
            if not callback(data|8):return
        else:
            if not callback(data|9):return
            if op==3 and not callback(data|10):return
        if op==2 and status==3:c.memmove(self.output,hashlib.sha256(model.previous.vectors()[index]).digest(),32)
        self.report=[status,region,data,int(live),int(op==1),4096 if op==3 else 0,int(op==3),0,1,op]
        if op==1:
            low=support.support.guard.LOW
            size=len(model.previous.vectors()[index]);head=int(fault!='header-copy')
            payload=int(status!=120 and head and size!=0)
            self.input_report=[1,head,payload,payload*int(fault!='payload-copy'),
                low+512,low+1024,low+4096,low+8192,0 if status==120 or not head else size,1,self.epoch]


def exercise(api=None,host=None):
    with patch.object(model.storage.guard,'callback',support.support.support.CALLBACK):
        return model.exercise(api or Api(),host or support.support.Host(),Path('image.dll'))


class Tests(unittest.TestCase):
    def test_complete_campaign_and_teardown(self):
        api=Api();host=support.support.Host();value=exercise(api,host)
        self.assertEqual(model.check_record(value),value)
        self.assertEqual(api.events,['terminate','delete']);self.assertFalse(host.pages)
    def test_copy_counts_sequence_cleanup_output_and_claims_are_bound(self):
        value=exercise()
        for index,step in enumerate(model.campaign()):
            for field in range(11):
                # Address changes within the same admitted region are not a
                # semantic tamper; substitute a definitely out-of-window value.
                changed=copy.deepcopy(value)
                changed['calls'][index]['input'][field]=1 if 4<=field<8 else changed['calls'][index]['input'][field]+1
                with self.assertRaises(ProbeError):model.check_record(changed)
            changed=copy.deepcopy(value);changed['calls'][index]['output']='00'*32
            with self.assertRaises(ProbeError):model.check_record(changed)
        for field in model.storage.guard.NONCLAIMS:
            with self.assertRaises(ProbeError):model.check_record({**value,field:True})
        changed=copy.deepcopy(value);changed['events'].pop()
        with self.assertRaises(ProbeError):model.check_record(changed)
    def test_unlock_failure_never_becomes_cleanup_success(self):
        api=Api();host=support.support.Host();host.failure='unlock'
        with self.assertRaisesRegex(RuntimeError,'retained input callback failed'):exercise(api,host)
        self.assertEqual(api.events,['terminate','delete'])


if __name__=='__main__':unittest.main()
