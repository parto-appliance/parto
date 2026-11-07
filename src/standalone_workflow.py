"""Persistent browser onboarding milestones, independent of tunnel desired state."""
from copy import deepcopy

HUB_STEPS = ['profile', 'invitation', 'request', 'approval', 'activate']
SPOKE_STEPS = ['invitation', 'profile', 'request', 'approval', 'activate']


def status(state, current=None, role=None):
    role = state['settings']['role'] if state else role
    steps = HUB_STEPS if role == 'hub' else SPOKE_STEPS
    if not state:
        return {'complete': False, 'step': steps[0], 'steps': steps, 'recipient': None}
    saved = state.get('web_setup', {})
    complete = saved.get('complete', bool(state.get('enabled') and 'web_setup' not in state))
    roster = (current or {}).get('roster', [])
    recipient = None
    if role == 'hub':
        spokes = [r for r in roster if r['settings']['role'] == 'spoke']
        pending = [r for r in spokes if r['node'] not in saved.get('approvals', [])]
        if not saved.get('invitation'):
            step = 'invitation'
        elif not spokes:
            step = 'request'
        elif pending:
            step, recipient = 'approval', pending[0]['node']
        else:
            step = 'request' if complete else 'activate'
    else:
        if not saved.get('request'):
            step = 'request'
        elif not any(r['node'] == state['node'] for r in roster):
            step = 'approval'
        else:
            step = 'activate'
    return {'complete': bool(complete), 'step': step, 'steps': steps, 'recipient': recipient}


def advance(state, current, value):
    if not isinstance(value, dict) or set(value) - {'event', 'node'}:
        raise ValueError('Invalid setup progress')
    candidate = deepcopy(state)
    saved = candidate.setdefault('web_setup', {'complete': False})
    event = value.get('event')
    role = state['settings']['role']
    if event == 'invitation' and role == 'hub' and 'node' not in value:
        saved['invitation'] = True
    elif event == 'request' and role == 'spoke' and 'node' not in value:
        saved['request'] = True
    elif event == 'approval' and role == 'hub':
        node = value.get('node')
        if not any(r['node'] == node and r['settings']['role'] == 'spoke' for r in current['roster']):
            raise ValueError('Choose an approved Spoke')
        saved['approvals'] = list(dict.fromkeys([*saved.get('approvals', []), node]))
    elif event == 'complete' and 'node' not in value:
        if status(candidate, current)['step'] != 'activate' or not state.get('enabled'):
            raise ValueError('Complete file exchange and activate before opening Monitor')
        saved['complete'] = True
    else:
        raise ValueError('Unsupported setup milestone')
    return candidate
