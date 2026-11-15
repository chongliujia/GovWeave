#!/usr/bin/env python3
"""Run EU AI Act, NIST and ISO preparation workflows on an isolated synthetic gateway."""
import argparse
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import secrets

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('assessment_demo', ROOT / 'scripts/demo-assessment.py')
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)
EXPECTED = {
    'eu-ai-act-chatbot-transparency': (3, 3),
    'eu-ai-act-high-risk-readiness': (3, 2),
    'eu-ai-act-gpai': (3, 2),
    'nist-ai-rmf-lifecycle': (3, 5),
    'nist-genai-profile': (3, 2),
    'iso-42001-readiness': (4, 2),
}


def require(condition, message):
    if not condition:
        raise demo.DemoError(message)


def counts(report):
    evaluation = report['evaluation']
    require(evaluation['legal_compliance'] == 'not_determined', 'Unexpected compliance claim')
    return {state: sum(c['status'] == state for c in evaluation['controls'])
            for state in ('pass', 'fail', 'unknown', 'not_applicable')}


def synthetic_facts(pack, now):
    facts = {}
    def fill(expression):
        if 'fact' in expression:
            facts[expression['fact']] = {
                'value': expression.get('value', True),
                'source': expression.get('source', 'declared'),
                'evidence_id': 'synthetic-preparation-reference', 'observed_at': now,
            }
        for child in expression.get('all', []):
            fill(child)
    for control in pack['controls']:
        fill(control['requirement'])
        fill(control.get('applies_when', {}))
    return facts


def main(args):
    bundle = json.loads((ROOT / 'examples/compliance-bundles/eu-nist-iso.json').read_text())
    output = args.output_dir or ROOT / 'dist/framework-demo' / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + secrets.token_hex(3))
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    summary = {'synthetic_data': True, 'legal_compliance': 'not_determined', 'bundle': bundle['id'],
               'bundle_version': bundle['version'], 'packs': [], 'external_model_calls': 0}
    with demo.DemoSession(args.binary.resolve(), pack_files=[p['file'] for p in bundle['packs']]) as session:
        catalog = session.call('/api/v1/plugins')['rule_packs']
        require({(p['id'], p['version']) for p in catalog} == {(p['id'], p['version']) for p in bundle['packs']}, 'Bundle catalog mismatch')
        original = session.call(session.product_path)
        for entry in bundle['packs']:
            pack = session.call(f"/api/v1/compliance/packs/{entry['id']}/versions/{entry['version']}")
            is_nist = entry['id'] == 'nist-ai-rmf-lifecycle'
            product = original if is_nist else session.call('/api/v1/compliance/products', {
                'name': 'Synthetic ' + entry['id'], 'version': 'demo-1', 'pack_id': entry['id'],
                'pack_version': entry['version'], 'application_ids': original['application_ids'], 'facts': {},
            })
            base = '/api/v1/compliance/products/' + product['id']
            empty = session.call(base + '/evaluate', {})
            require(counts(empty)['pass'] == 0, 'Missing evidence unexpectedly passed')
            facts = {} if is_nist else synthetic_facts(pack, datetime.now(timezone.utc).isoformat())
            control = next(c for c in pack['controls'] if c['assessment_method'] == 'evidence')
            if is_nist:
                control = next(c for c in pack['controls'] if c['id'] == 'NIST-OPERATION-TEST')
                require(session.run('pre_deployment')['status'] == 'passed', 'Pre-deployment fixture failed')
                session.provider.set_mode('broken')
                require(session.run('operation')['status'] == 'failed', 'Negative operation fixture did not fail')
            else:
                key = control['requirement'].get('fact') or control['requirement']['all'][0]['fact']
                facts[key]['value'] = False
                def save(current, new_facts):
                    return session.call(base, {k: current[k] for k in ('revision', 'name', 'version', 'pack_id', 'pack_version', 'application_ids')} | {'facts': new_facts}, 'PUT')
                product = save(product, facts)
            gap = session.call(base + '/reports', {})
            require(counts(gap['snapshot']['report'])['fail'] >= 1, 'Known gap was lost')
            item = session.call(base + '/remediations', {'report_id': gap['summary']['id'], 'control_id': control['id'], 'owner': 'Synthetic demo team', 'note': 'Synthetic workflow only; no real organization evidence.'})
            path = base + '/remediations/' + item['id']
            item = session.call(path, {'revision': item['current']['revision'], 'status': 'ready_for_recheck', 'owner': 'Synthetic demo team', 'due_date': '', 'note': 'Prepare fresh synthetic evidence.'}, 'PUT')
            check = {'revision': item['current']['revision']}
            if is_nist:
                session.provider.set_mode('fixed')
                run = session.run('operation')
                require(run['status'] == 'passed', 'Repaired operation fixture failed')
                check['test_run_id'] = run['id']
            else:
                facts[key]['value'] = True
                product = save(product, facts)
            verified = session.call(path + '/recheck', check)
            require(verified['current']['status'] == 'verified' and verified['verification_state'] == 'current', 'Remediation did not verify')
            final = session.call(base + '/reports', {})
            result = counts(final['snapshot']['report'])
            passed, manual = EXPECTED[entry['id']]
            require(result == {'pass': passed, 'fail': 0, 'unknown': manual, 'not_applicable': 0}, f"Unexpected {entry['id']} counts: {result}")
            for c in final['snapshot']['report']['evaluation']['controls']:
                if c['assessment_method'] == 'manual':
                    require(c['status'] == 'unknown', 'Manual review unexpectedly passed')
            replay = session.call('/api/v1/compliance/reports/' + final['summary']['id'] + '/replay', {})
            require(replay['matches'], 'Archived evaluation could not be replayed')
            if is_nist:
                session.provider.set_mode('broken')
                session.run('operation')
                session.provider.set_mode('fixed')
            else:
                expired = copy.deepcopy(facts)
                for fact in expired.values():
                    fact['observed_at'] = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
                    fact['expires_at'] = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
                product = save(product, expired)
                require(counts(session.call(base + '/evaluate', {}))['pass'] == 0, 'Expired evidence passed')
            changed = session.call(path)
            require(changed['verification_state'] == 'stale', 'Changed evidence retained current verification')
            demo.save_json(output / (entry['id'] + '.json'), {'missing': empty, 'gap': gap, 'verified': verified, 'retained_report': final, 'replay': replay, 'after_evidence_change': changed})
            summary['packs'].append({'id': entry['id'], 'version': entry['version'], 'counts': result, 'replay_matches': True, 'remediation_verified': True, 'changed_evidence_stale': True})
            print(f"{entry['id']}: {passed} pass / {manual} manual; gap -> remediation -> verification -> replay -> stale")
        summary['local_scripted_model_calls'] = session.provider.state()[1]
    demo.save_json(output / 'summary.json', summary)
    print(('三类框架流程验收通过；合成材料不代表组织合规。报告：' if args.lang == 'zh-CN' else 'Framework workflow checks passed; synthetic evidence is not organizational compliance. Reports: ') + str(output))
    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'bin/govweave')
    parser.add_argument('--output-dir', type=Path)
    parser.add_argument('--lang', choices=('en', 'zh-CN'), default='en')
    try:
        raise SystemExit(main(parser.parse_args()))
    except (demo.DemoError, OSError, ValueError) as error:
        parser.exit(1, f'Framework demo failed: {error}\n')
