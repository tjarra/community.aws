#!/usr/bin/python
# Copyright (c) 2022 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = r'''
---
module: aws_eks_fargate_profile
version_added: 1.0.0
short_description: Manage EKS Fargate Profile
description:
    - Manage EKS Fargate Profile
author: Tiago Jarra (@tjarra)
options:
  name:
    description: Name of EKS Fargate Profile
    required: True
    type: str
  cluster_name:
    description: Name of EKS Cluster
    required: True
    type: str
  role_arn:
    description: ARN of IAM role used by the EKS cluster
    required: True
    type: str
  subnets:
    description: list of subnet IDs for the Kubernetes cluster
    required: True
    type: list
    elements: str
  selectors:
    description: A list of selectors to use in fargate profile 
    required: True
    type: list
    suboptions:
      namespace:
        description: A namespace used in fargate profile
        type: str
      labels:
        description: A dictionary of labels used in fargate profile
        type: dict
        elements: str
  state:
    description: Create or delete the Fargate Profile
    choices:
      - absent
      - present
    default: present
    type: str
  tags:
    description: A dictionary of resource tags
    type: dict
    elements: str
  wait:
    description: >-
      Specifies whether the module waits until the profile is created or deleted before moving on.
    type: bool
    default: false
  wait_timeout:
    description: >-
      The duration in seconds to wait for the cluster to become active. Defaults
      to 1200 seconds (20 minutes).
    default: 1200
    type: int
extends_documentation_fragment:
- amazon.aws.aws
- amazon.aws.ec2

'''

EXAMPLES = r'''
# Note: These examples do not set authentication details, see the AWS Guide for details.

- name: Create an EKS Fargate Profile
  community.aws.aws_eks_fargate_profile:
    name: test_fargate
    cluster_name: test_cluster
    role_arn: my_eks_role
    subnets:
      - subnet-aaaa1111
    selectors:
      - namespace: nm-test
        labels:
          - label1: test
    state: present
    wait: yes

- name: Remove an EKS cluster
  community.aws.aws_eks_cluster:
    name: test_fargate
    clusterName: test_cluster
    wait: yes
    state: absent
'''

RETURN = r'''
fargateProfileName:
  description: Name of Fargate Profile
  returned: when state is present
  type: str
  sample: test_profile
fargateProfileArn:
  description: ARN of the Fargate Profile
  returned: when state is present
  type: str
  sample: arn:aws:eks:us-east-1:1231231123:safd
clusterName:
  description: Name of EKS Cluster 
  returned: when state is present
  type: str
  sample: test-cluster
created_at:
  description: Fargate Profule creation date and time
  returned: when state is present
  type: str
  sample: '2022-01-18T20:00:00.111000+00:00'
podExecutionRoleArn:
  description: ARN of the IAM Role used by Fargate Profile
  returned: when state is present
  type: str
  sample: arn:aws:eks:us-east-1:1231231123:role/asdf
subnets:
  description: List of subnets used in Fargate Profile
  returned: when state is present
  type: list
  sample:
  - subnet-qwerty123
  - subnet-asdfg456
selectors:
  description: Selector configuration
  returned: when state is present
  type: complex
  contains:
    namespace:
      description: Name of the kubernetes namespace used in profile
      returned: when state is present
      type: str
      sample: nm-test
    labels:
      description: List of kubernetes labels used in profile
      returned: when state is present
      type: list
      sample:
        - label1: test1
        - label2: test2
tags:
  description: A dictionary of resource tags
  returned: when state is present
  type: dict
  sample:
      foo: bar
      env: test
status:
  description: status of the EKS Fargate Profile
  returned: when state is present
  type: str
  sample:
  - CREATING
  - ACTIVE
'''

from ansible_collections.amazon.aws.plugins.module_utils.core import AnsibleAWSModule, is_boto3_error_code
from ansible_collections.amazon.aws.plugins.module_utils.ec2 import compare_aws_tags
from ansible_collections.amazon.aws.plugins.module_utils.ec2 import camel_dict_to_snake_dict
from ansible_collections.amazon.aws.plugins.module_utils.waiters import get_waiter

try:
    import botocore.exceptions
except ImportError:
    pass  

def validate_tags(client, module, fargate_profile):
  
    changed = False
    existing_tags = client.list_tags_for_resource(resourceArn=fargate_profile['fargateProfileArn'])['tags']
    
    tags_to_add, tags_to_remove = compare_aws_tags(existing_tags, module.params.get('tags'), module.params.get('purge_tags'))
    
    if tags_to_remove:
        if not module.check_mode:
            changed = True
            try:
                client.untag_resource(resourceArn=fargate_profile['fargateProfileArn'], tagKeys=tags_to_remove)
            except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
                module.fail_json_aws(e, msg='Unable to set tags for Fargate Profile %s' % module.params.get('name'))

    if tags_to_add:
        if not module.check_mode:
            changed = True
            try:
                client.tag_resource(resourceArn=fargate_profile['fargateProfileArn'], tags=tags_to_add)
            except (botocore.exceptions.ClientError, botocore.exceptions.BotoCoreError) as e:
                module.fail_json_aws(e, msg='Unable to set tags for Fargate Profile %s' % module.params.get('name'))
    
    return changed

def create_or_update_fargate_profile(client, module):
    name = module.params.get('name')
    subnets = module.params['subnets']
    role_arn = module.params['role_arn']
    cluster_name = module.params['cluster_name']
    selectors = module.params['selectors']
    tags = module.params['tags']
    wait = module.params.get('wait')
    fargate_profile = get_fargate_profile(client, module, name, cluster_name)
    
    if fargate_profile:
        changed = False
        if set(fargate_profile['podExecutionRoleArn']) != set(role_arn):
            module.fail_json(msg="Cannot modify Execution Role")
        if set(fargate_profile['subnets']) != set(subnets):
            module.fail_json(msg="Cannot modify Subnets")
        if fargate_profile['selectors'] != selectors:
            module.fail_json(msg="Cannot modify Selectors")        
        
        changed = validate_tags(client, module, fargate_profile)
                              
        if wait:
            wait_until(client, module, 'fargate_profile_active', name, cluster_name)
            fargateProfile = get_fargate_profile(client, module, name, cluster_name)

        module.exit_json(changed=changed, **camel_dict_to_snake_dict(fargateProfile))

    if module.check_mode:
        module.exit_json(changed=True)
    
    check_profiles_status(client, module, cluster_name)
    
    try:
        params = dict(fargateProfileName=name,
                      podExecutionRoleArn=role_arn,
                      subnets=subnets,
                      clusterName=cluster_name,
                      selectors=selectors,
                      tags=tags
                      )
        fargateProfile = client.create_fargate_profile(**params)
    except (botocore.exceptions.BotoCoreError, botocore.exceptions.ClientError) as e:
        module.fail_json_aws(e, msg="Couldn't create fargate profile %s" % name)

    if wait:
        wait_until(client, module, 'fargate_profile_active', name, cluster_name)
        fargateProfile = get_fargate_profile(client, module, name, cluster_name)

    module.exit_json(changed=True, **camel_dict_to_snake_dict(fargateProfile))


def delete_fargate_profile(client, module):
    name = module.params.get('name')
    cluster_name = module.params['cluster_name']
    existing = get_fargate_profile(client, module, name, cluster_name)
    wait = module.params.get('wait')
    if not existing:
        module.exit_json(changed=False)
    if not module.check_mode:

        check_profiles_status(client, module, cluster_name)
        
        try:
            client.delete_fargate_profile(clusterName=cluster_name,fargateProfileName=name)
        except (botocore.exceptions.BotoCoreError, botocore.exceptions.ClientError) as e:
            module.fail_json_aws(e, msg="Couldn't delete fargate profile %s" % name)

    if wait:
        wait_until(client, module, 'fargate_profile_deleted', name, cluster_name)

    module.exit_json(changed=True)

def get_fargate_profile(client, module, name, cluster_name):    
    try:
        return client.describe_fargate_profile(clusterName=cluster_name, fargateProfileName=name)['fargateProfile']
    except is_boto3_error_code('ResourceNotFoundException'):
        return None

# Check if any fargate profiles is in changing states, if so, wait for the end
def check_profiles_status(client, module, cluster_name):
  
    try:    
        list_profiles = client.list_fargate_profiles(clusterName=cluster_name)     
        
        for name in list_profiles["fargateProfileNames"] :
            fargate_profile = get_fargate_profile(client, module, name, cluster_name)
            if fargate_profile["status"] == 'CREATING' :
                wait_until(client, module, 'fargate_profile_active', fargate_profile["fargateProfileName"], cluster_name)
            elif fargate_profile["status"] == 'DELETING' :
                wait_until(client, module, 'fargate_profile_deleted', fargate_profile["fargateProfileName"], cluster_name)
    except (botocore.exceptions.BotoCoreError, botocore.exceptions.ClientError) as e:
        module.fail_json_aws(e, msg="Couldn't not find EKS cluster")
  
def wait_until(client, module, waiter_name, name, cluster_name):    
    wait_timeout = module.params.get('wait_timeout')
    
    waiter = get_waiter(client, waiter_name)
    attempts = 1 + int(wait_timeout / waiter.config.delay)
    waiter.wait(clusterName=cluster_name, fargateProfileName=name, WaiterConfig={'MaxAttempts': attempts})
    
def main():
    argument_spec = dict(
        name=dict(required=True),
        cluster_name=dict(required=True),
        role_arn=dict(),
        subnets=dict(type='list', elements='str'),   
        selectors=dict(type='list'),     
        tags=dict(type='dict', default={}),
        purge_tags=dict(type='bool', default=True),
        state=dict(choices=['absent', 'present'], default='present'),
        wait=dict(default=False, type='bool'),
        wait_timeout=dict(default=1200, type='int')
    )

    module = AnsibleAWSModule(
        argument_spec=argument_spec,
        required_if=[['state', 'present', ['cluster_name', 'role_arn', 'subnets', 'selectors']]],
        supports_check_mode=True,
    )

    client = module.client('eks')

    if module.params.get('state') == 'present':
        create_or_update_fargate_profile(client, module)
    else:
        delete_fargate_profile(client, module)

if __name__ == '__main__':
    main()