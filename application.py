import boto3
import cloudpassage
import os
from collections import defaultdict
from datetime import datetime


def format_cve_findings(findings):
    instance_to_packages = defaultdict(dict)
    for finding in findings:
        csp_instance_id = finding['assetAttributes']['agentId']
        first_seen_at = finding['createdAt']
        last_seen_at = finding['createdAt']
        cve_id = finding['id']

        for attribute in finding['attributes']:
            if attribute['key'] == 'CVSS3_SCORE':
                cvss3_score = attribute['value']

            elif attribute['key'] == 'CVSS2_SCORE':
                cvss2_score = attribute['value']

        cve_info = {
            'id': cve_id,
            'score': float(cvss3_score or cvss2_score),
            'cvss_version': 3 if cvss3_score else 2
        }

        package_to_cves = instance_to_packages[csp_instance_id]
        for attribute in finding['attributes']:
            if attribute['key'] == 'package_name':
                for package in attribute['value'].split(','):
                    colon_index = package.index(':')
                    package_name = package[:colon_index - 2]
                    package_version = package[colon_index - 1:]

                    try:
                        if cve_info not in package_to_cves[package_name]['cve_info']:
                            package_to_cves[package_name]['cve_info'].append(cve_info)
                        if first_seen_at < package_to_cves[package_name]['first_seen_at']:
                            package_to_cves[package_name]['first_seen_at'] = first_seen_at
                        if last_seen_at > package_to_cves[package_name]['last_seen_at']:
                            package_to_cves[package_name]['last_seen_at'] = last_seen_at
                    except KeyError:
                        package_to_cves[package_name] = {
                            'package_name': package_name,
                            'package_version': package_version,
                            'first_seen_at': first_seen_at,
                            'last_seen_at': last_seen_at,
                            'cve_info': [cve_info]
                        }

    return instance_to_packages


def create_new_sva_issue(package_detail, target, session, issue_type):
    request = cloudpassage.HttpHelper(session)

    # Find Max CVSS Score
    max_cvss = max(cve_info['score'] for cve_info in package_detail['cve_info'])

    # Determine if issue is critical based on CVSS score
    critical = True
    if float(max_cvss) < 5:
        critical = False

    issue = {
        'rule_key': f'aws_inspector::::{issue_type}::::'
                    f'{package_detail["package_name"] + package_detail["package_version"]}',
        'name': f'AWS Inspector-Vulnerable software: {package_detail["package_name"]}',
        'type': issue_type,
        'status': 'active',
        'critical': critical,
        'source': 'server_secure',
        'asset_id': target['id'],
        'asset_type': 'server',
        'asset_name': target['hostname'],
        'asset_fqdn': target.get('reported_fqdn'),
        'package_name': package_detail["package_name"],
        'package_version': package_detail["package_version"],
        'max_cvss': max_cvss,
        'extended_attributes': {
            'cve_info': package_detail['cve_info']
        },
        'external_issue': True,
        'external_issue_source': 'aws_inspector',
        'first_seen_at': package_detail['first_seen_at'].isoformat(),
        'last_seen_at': package_detail['last_seen_at'].isoformat(),
        'csp_account_id': target['csp_account_id'],
        'csp_account_type': target['csp_provider'].split('_')[0],
        'csp_region': target['csp_region'],
        'csp_resource_id': target['csp_instance_id'],
        'csp_image_id': target['csp_image_id'],
        'os_type': target['kernel_name'].lower()
    }

    request.post('/v3/issues', {'issue': issue})


def update_sva_issue(package_detail, halo_issue, target, session):
    cve_set = set(cve['id'] for cve in halo_issue['extended_attributes']['cve_info'])

    for cve in package_detail['cve_info']:
        if cve['id'] not in cve_set:
            halo_issue['extended_attributes']['cve_info'].append(cve)

    new_max_cvss = max(cve_info['score'] for cve_info in halo_issue['extended_attributes']['cve_info'])
    halo_issue['max_cvss'] = new_max_cvss
    if new_max_cvss >= 5:
        halo_issue['critical'] = True

    # Full isoformat has length 27. Need to pad last_seen_at with trailing zeros for correct isoformat
    trailing_zeros = 27 - len(halo_issue['last_seen_at'])
    halo_last_seen_dt = datetime.fromisoformat(halo_issue['last_seen_at'][:-1] + trailing_zeros*'0')
    if halo_last_seen_dt < package_detail['last_seen_at'].replace(tzinfo=None):
        halo_issue['last_seen_at'] = package_detail['last_seen_at'].isoformat()

    request = cloudpassage.HttpHelper(session)
    request.post('/v3/issues', {'issue': halo_issue})


def push_cves_issues_halo(findings, issue_type):
    session = cloudpassage.HaloSession(os.environ['HALO_API_KEY'],
                                       os.environ['HALO_API_SECRET'],
                                       api_host=os.getenv('HALO_API_HOST', 'api.cloudpassage.com'),
                                       api_port=os.getenv('HALO_CONNECTION_PORT', '443'))
    server = cloudpassage.Server(session)
    issue = cloudpassage.Issue(session, endpoint_version=3)

    for instance_id, package_to_cves in findings.items():
        target_halo_asset = server.list_all(csp_instance_id=instance_id)
        if target_halo_asset:
            target = target_halo_asset[0]
            asset_id = target['id']

            for package_name, package_detail in package_to_cves.items():
                halo_issue = issue.list_all(
                    type=issue_type,
                    asset_id=asset_id,
                    rule_key=f'aws_inspector::::{issue_type}::::{package_name + package_detail["package_version"]}',
                    status='active,resolved'
                )
                # if vulnerable package exists in target_openvas_issues, update issue
                if halo_issue:
                    update_sva_issue(package_detail, halo_issue[0], target, session)
                else:
                    create_new_sva_issue(package_detail, target, session, issue_type)


def get_rule_arns():
    client = boto3.client('inspector')
    rule_arns = client.list_rules_packages()['rulesPackageArns']
    rule_arn_details = client.describe_rules_packages(rulesPackageArns=rule_arns)

    #  Rule keys
    #  Common Vulnerabilities and Exposures (cve)
    #  CIS Operating System Security Configuration Benchmarks (cis)
    #  Security Best Practices (sbp)
    #  Network Reachability (net)
    rule_arns = {}
    for rule_package in rule_arn_details['rulesPackages']:
        if rule_package['name'] == 'Common Vulnerabilities and Exposures':
            rule_arns['cve'] = rule_package['arn']
        if rule_package['name'] == 'CIS Operating System Security Configuration Benchmarks':
            rule_arns['cis'] = rule_package['arn']
        if rule_package['name'] == 'Security Best Practices':
            rule_arns['sbp'] = rule_package['arn']
        if rule_package['name'] == 'Network Reachability':
            rule_arns['net'] = rule_package['arn']

    return rule_arns


def create_new_csm_issue(cis_finding, target, session):
    request = cloudpassage.HttpHelper(session)

    critical = True if cis_finding['severity'] == 'High' else False
    for attribute in cis_finding['attributes']:
        if attribute['key'] == "BENCHMARK_ID":
            benchmark_id = attribute['value']

    issue = {
        'rule_key': f'aws_inspector::::csm::::{cis_finding["id"]}',
        'name': f'AWS Inspector: {cis_finding["id"].split(" ", 1)[1]}',
        'type': 'csm',
        'status': 'active',
        'critical': critical,
        'source': 'server_secure',
        'asset_id': target['id'],
        'asset_type': 'server',
        'asset_name': target['hostname'],
        'asset_fqdn': target.get('reported_fqdn'),
        'asset_hostname': target['hostname'],
        'external_issue': True,
        'external_issue_source': 'aws_inspector',
        'rule_name': cis_finding["id"].split(" ", 1)[1],
        'policy_name': benchmark_id,
        'first_seen_at': cis_finding['createdAt'].isoformat(),
        'last_seen_at': cis_finding['createdAt'].isoformat(),
        'extended_attributes': {
            'recommendation': cis_finding['recommendation'],
            'numeric_severity': cis_finding['numericSeverity']
        },
        'csp_account_id': target['csp_account_id'],
        'csp_account_type': target['csp_provider'].split('_')[0],
        'csp_region': target['csp_region'],
        'csp_resource_id': target['csp_instance_id'],
        'csp_image_id': target['csp_image_id'],
        'os_type': target['kernel_name'].lower()
    }

    request.post('/v3/issues', {'issue': issue})


def push_cis_issues_halo(cis_findings):
    session = cloudpassage.HaloSession(os.environ['HALO_API_KEY'],
                                       os.environ['HALO_API_SECRET'],
                                       api_host=os.getenv('HALO_API_HOST', 'api.cloudpassage.com'),
                                       api_port=os.getenv('HALO_CONNECTION_PORT', '443'))
    server = cloudpassage.Server(session)
    issue = cloudpassage.Issue(session, endpoint_version=3)

    for cis_finding in cis_findings:
        instance_id = cis_finding['assetAttributes']['agentId']
        target_halo_asset = server.list_all(csp_instance_id=instance_id)
        if target_halo_asset:
            target = target_halo_asset[0]
            create_new_csm_issue(cis_finding, target, session)


def ingest_cves(cve_arn):
    client = boto3.client('inspector')
    paginator = client.get_paginator('list_findings')
    page_iterator = paginator.paginate(filter={'rulesPackageArns': [cve_arn]}, PaginationConfig={'PageSize': 1000,})
    for page in page_iterator:
        finding_arns = page['findingArns']
        cve_findings = client.describe_findings(findingArns=finding_arns)['findings']
        cve_findings_formatted = format_cve_findings(cve_findings)
        push_cves_issues_halo(cve_findings_formatted, 'sva')


def ingest_cis(cis_arn):
    client = boto3.client('inspector')
    paginator = client.get_paginator('list_findings')
    page_iterator = paginator.paginate(filter={'rulesPackageArns': [cis_arn]}, PaginationConfig={'PageSize': 1000,})
    for page in page_iterator:
        finding_arns = page['findingArns']
        cis_findings = client.describe_findings(findingArns=finding_arns)['findings']
        push_cis_issues_halo(cis_findings)

def main():
    rule_arns = get_rule_arns()

    #  Software Vulnerabilities (CVEs)
    if 'cve' in rule_arns:
        ingest_cves(rule_arns['cve'])


    #  CIS Benchmarks
    if 'cis' in rule_arns:
        ingest_cis(rule_arns['cis'])


if __name__ == "__main__":
    main()
