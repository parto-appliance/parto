"""Onboarding resumes from durable exchange milestones and cannot finish early."""
from copy import deepcopy
from pathlib import Path
import sys, unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import standalone_workflow as workflow

class WorkflowTests(unittest.TestCase):
 def state(self,role):return {'node':'self','settings':{'role':role},'enabled':False,'web_setup':{'complete':False}}
 def row(self,node,role):return {'node':node,'settings':{'role':role}}
 def test_initial_roles_have_different_first_steps(self):
  self.assertEqual(workflow.status(None,role='hub')['step'],'profile')
  self.assertEqual(workflow.status(None,role='spoke')['step'],'invitation')
 def test_hub_downloads_invitation_then_request_approval_and_activation(self):
  state=self.state('hub');current={'roster':[self.row('self','hub')]}
  self.assertEqual(workflow.status(state,current)['step'],'invitation')
  state=workflow.advance(state,current,{'event':'invitation'});self.assertEqual(workflow.status(state,current)['step'],'request')
  current['roster'].append(self.row('a','spoke'));self.assertEqual(workflow.status(state,current)['recipient'],'a')
  state=workflow.advance(state,current,{'event':'approval','node':'a'});self.assertEqual(workflow.status(state,current)['step'],'activate')
  with self.assertRaises(ValueError):workflow.advance(state,current,{'event':'complete'})
  state['enabled']=True;state=workflow.advance(state,current,{'event':'complete'});self.assertTrue(workflow.status(state,current)['complete'])
 def test_spoke_cannot_skip_request_or_approval(self):
  state=self.state('spoke');current={'roster':[self.row('hub','hub')]}
  self.assertEqual(workflow.status(state,current)['step'],'request')
  state['enabled']=True
  with self.assertRaises(ValueError):workflow.advance(state,current,{'event':'complete'})
  state=workflow.advance(state,current,{'event':'request'});self.assertEqual(workflow.status(state,current)['step'],'approval')
  with self.assertRaises(ValueError):workflow.advance(state,current,{'event':'complete'})
  current['roster'].append(self.row('self','spoke'));state=workflow.advance(state,current,{'event':'complete'});self.assertTrue(state['web_setup']['complete'])
 def test_add_second_spoke_preserves_completed_setup(self):
  state=self.state('hub');state.update(enabled=True,web_setup={'complete':True,'invitation':True,'approvals':['a']})
  current={'roster':[self.row('self','hub'),self.row('a','spoke'),self.row('b','spoke')]}
  status=workflow.status(state,current);self.assertTrue(status['complete']);self.assertEqual(status['recipient'],'b')
  updated=workflow.advance(state,current,{'event':'approval','node':'b'});self.assertEqual(updated['web_setup']['approvals'],['a','b']);self.assertEqual(state['web_setup']['approvals'],['a'])
 def test_progress_cannot_change_role_or_invent_a_peer(self):
  state=self.state('spoke');current={'roster':[]}
  for value in [{'event':'invitation'},{'event':'approval','node':'other'},{'event':'complete','settings':{}}]:
   with self.assertRaises(ValueError):workflow.advance(state,current,value)
 def test_legacy_active_nodes_remain_usable(self):
  state=self.state('hub');state.pop('web_setup');state['enabled']=True
  self.assertTrue(workflow.status(state,{'roster':[]})['complete'])
